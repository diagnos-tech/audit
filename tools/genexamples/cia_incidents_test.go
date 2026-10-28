package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

const (
	eventDir     = "data/v1/cia/incidents/events/2026/10/01/"
	vaultOpened  = eventDir + "2026-10-01-auto-vault-a-0310-1.json"
	vaultClosed  = eventDir + "2026-10-01-auto-vault-a-0310-2.json"
	statusOpened = eventDir + "2026-10-01-auto-status-i-1335-1.json"
	newestDecl   = "data/v1/cia/incidents/2026/10/01/1155Z.json"
	vantageRun   = "data/v1/cia/runs/2026/10/01/0900Z.json"
	signDeclared = "2026-09-30-sign-session-ids-in-logs"
)

func editEvent(t *testing.T, dir, path string, change func(*record.CIAIncidentEvent)) {
	t.Helper()
	rewrite(t, dir, path, "cia-incident-event/v1", change)
}

func changesFile(t *testing.T, dir, path, schema string, change func(*record.CIAChanges)) {
	t.Helper()
	rewrite(t, dir, path, schema, change)
}

func remove(t *testing.T, dir string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.Remove(filepath.Join(dir, p)); err != nil {
			t.Fatal(err)
		}
	}
}

// The incidents the auditor opens by itself, the colours they give, the change
// events and the late data are all derived again from the facts; every way of
// lying about them is named.
func TestIncidentTamperingIsCaught(t *testing.T) {
	for _, c := range []struct {
		name   string
		tamper func(t *testing.T, dir string)
		expect string
	}{
		{"event reworded (its reasons)", func(t *testing.T, dir string) {
			editEvent(t, dir, vaultOpened, func(e *record.CIAIncidentEvent) { e.Reasons = []string{"connect-error"} })
		}, "differs from what the records give"},
		{"latest event reworded (the incident list follows it)", func(t *testing.T, dir string) {
			editEvent(t, dir, vaultClosed, func(e *record.CIAIncidentEvent) { e.Reasons = []string{"connect-error"} })
		}, "differs from the snapshot and the events"},
		{"first event deleted (a gap in seq)", func(t *testing.T, dir string) { remove(t, dir, vaultOpened) },
			"not numbered 1, 2, 3 without gaps"},
		{"resolved while the service still failed", func(t *testing.T, dir string) {
			editEvent(t, dir, vaultClosed, func(e *record.CIAIncidentEvent) { e.ResolvedAt = ptr("2026-10-01T03:20:00Z") })
		}, "was resolved from"},
		{"opened for a service that did not fail", func(t *testing.T, dir string) {
			editEvent(t, dir, vaultOpened, func(e *record.CIAIncidentEvent) { e.StartedAt = "2026-10-01T03:05:00Z" })
		}, "id"},
		{"event written under the wrong name", func(t *testing.T, dir string) {
			data, _ := os.ReadFile(filepath.Join(dir, vaultOpened))
			if err := os.WriteFile(filepath.Join(dir, eventDir+"2026-10-01-auto-vault-a-0310-3.json"), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "belongs at"},
		{"a failure the auditor did not turn into an incident", func(t *testing.T, dir string) {
			remove(t, dir, vaultOpened, vaultClosed)
		}, "no availability incident of the service covers it"},
		{"an integrity failure without an incident", func(t *testing.T, dir string) {
			remove(t, dir, statusOpened, strings.Replace(statusOpened, "-1.json", "-2.json", 1))
		}, "no integrity incident of the service covers it"},
		{"declared incident that relates to nothing", func(t *testing.T, dir string) {
			rewrite(t, dir, newestDecl, "cia-incidents/v1", func(s *record.CIAIncidents) {
				for i := range s.Incidents {
					if s.Incidents[i].Relates != nil {
						s.Incidents[i].Relates = ptr("2026-10-01-auto-vault-a-0311")
					}
				}
			})
		}, "which no event opened"},
		{"declared incident removed from the newest snapshot", func(t *testing.T, dir string) {
			rewrite(t, dir, newestDecl, "cia-incidents/v1", func(s *record.CIAIncidents) {
				var kept []record.CIAIncident
				for _, in := range s.Incidents {
					if in.ID != signDeclared {
						kept = append(kept, in)
					}
				}
				s.Incidents = kept
			})
		}, "differs"},
		{"incident colour removed from a day file", func(t *testing.T, dir string) {
			rewrite(t, dir, dayFile, "cia-day/v1", func(d *record.CIADay) {
				l := d.Services["status"]
				l.Integrity = strings.ReplaceAll(l.Integrity, "f", "o")
				d.Services["status"] = l
				var kept []record.CIASpan
				for _, s := range d.Spans {
					if s.Service != "status" || s.Dimension != "integrity" {
						kept = append(kept, s)
					}
				}
				d.Spans = kept
			})
		}, "differs from the run records"},
		{"incidents of latest edited by hand", func(t *testing.T, dir string) {
			rewrite(t, dir, record.CIALatestPath, "cia-latest/v1", func(l *record.CIALatest) {
				v := l.Services["status"]
				v.Integrity.Incidents = []string{}
				l.Services["status"] = v
			})
		}, "differs from the latest run record"},
		{"vantage failure recorded as an outage", func(t *testing.T, dir string) {
			runRecord(t, dir, vantageRun, func(r *record.CIARun) {
				for id, s := range r.Services {
					for _, d := range []*record.CIADimension{&s.Availability, &s.Integrity} {
						for i, c := range d.Checks {
							switch {
							case c.Healthz != nil:
								c.Healthz.Level, c.Healthz.Code = "fail", "timeout"
							case c.Checkpoint != nil:
								c.Checkpoint.Level, c.Checkpoint.Code = "fail", "unreachable"
							case c.Release != nil:
								c.Release.Level, c.Release.Code = "none", "unreachable"
							case c.Log != nil:
								c.Log.Level, c.Log.Code = "none", "unreachable"
							}
							d.Checks[i] = c
						}
						d.Level = map[bool]string{true: "fail", false: "none"}[d == &s.Availability]
					}
					r.Services[id] = s
				}
			})
		}, "recorded as an outage while the control probe failed"},
		{"vantage code with a control probe that worked", func(t *testing.T, dir string) {
			runRecord(t, dir, vantageRun, func(r *record.CIARun) { r.Control.OK = true })
		}, "the control probe did not fail"},
		{"vantage failure that left one check measured", func(t *testing.T, dir string) {
			runRecord(t, dir, vantageRun, func(r *record.CIARun) {
				s := r.Services["frontend"]
				s.Integrity.Checks[0].Release.Level, s.Integrity.Checks[0].Release.Code = "warn", "unsigned"
				s.Integrity.Level = "warn"
				r.Services["frontend"] = s
			})
		}, "others do not"},
		{"change event deleted from changes.json", func(t *testing.T, dir string) {
			changesFile(t, dir, record.CIAChangesPath, "cia-changes/v1", func(c *record.CIAChanges) { c.Events = c.Events[1:] })
		}, "is missing: a change the records show is not listed"},
		{"change event invented", func(t *testing.T, dir string) {
			changesFile(t, dir, record.CIAChangesPath, "cia-changes/v1", func(c *record.CIAChanges) {
				e := c.Events[0]
				e.ID, e.At, e.Since = "202610011400-vault-availability-level", "2026-10-01T14:00:00Z", "2026-10-01T14:00:00Z"
				c.Events = append([]record.CIAChange{e}, c.Events...)
			})
		}, "is not derived from the records"},
		{"change event reworded", func(t *testing.T, dir string) {
			changesFile(t, dir, record.CIAChangesPath, "cia-changes/v1", func(c *record.CIAChanges) { c.Events[0].Summary.EN = "All is well" })
		}, "differs from what the records give"},
		{"change events out of order", func(t *testing.T, dir string) {
			changesFile(t, dir, record.CIAChangesPath, "cia-changes/v1", func(c *record.CIAChanges) { c.Events[0], c.Events[3] = c.Events[3], c.Events[0] })
		}, "out of order"},
		{"recent changes missing an event", func(t *testing.T, dir string) {
			changesFile(t, dir, record.CIARecentPath, "cia-changes-recent/v1", func(c *record.CIAChanges) { c.Events = c.Events[1:] })
		}, "is missing"},
		{"recent changes with an extra event", func(t *testing.T, dir string) {
			changesFile(t, dir, record.CIARecentPath, "cia-changes-recent/v1", func(c *record.CIAChanges) {
				e := c.Events[0]
				e.ID = "202610011430-vault-availability-level"
				c.Events = append(c.Events, e)
			})
		}, "not derived"},
		{"incident list edited by hand", func(t *testing.T, dir string) {
			rewrite(t, dir, record.CIAIncidentsViewPath, "cia-incident-list/v1", func(l *record.CIAIncidentList) {
				for _, it := range l.Incidents {
					if it.Auto != nil {
						it.Auto.Postmortems = []string{}
					}
				}
			})
		}, "differs from the snapshot and the events"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, dir := generateExamples(t)
			c.tamper(t, dir)
			failed, _ := verifyAll(t, dir)
			if all := strings.Join(failed, "\n"); !strings.Contains(all, c.expect) {
				t.Errorf("not reported as %q; failures:\n%.3000s", c.expect, all)
			}
		})
	}
}
