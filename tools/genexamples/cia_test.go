package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// rewrite decodes the data file at path, lets change edit it and writes it
// back the way the auditor does.
func rewrite[T any](t *testing.T, dir, path, schema string, change func(*T)) {
	t.Helper()
	full := filepath.Join(dir, path)
	data, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	var v T
	if err := record.Decode(data, schema, &v); err != nil {
		t.Fatal(err)
	}
	change(&v)
	out, err := record.Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func runRecord(t *testing.T, dir, path string, change func(*record.CIARun)) {
	t.Helper()
	rewrite(t, dir, path, "cia-run/v1", change)
}

const (
	slowSlot  = "data/v1/cia/runs/2026/10/01/1105Z.json" // sign answered slowly
	nextSlot  = "data/v1/cia/runs/2026/10/01/1110Z.json"
	hourSlot  = "data/v1/cia/runs/2026/10/01/0520Z.json" // the run that stamped hour 05, after the gap
	dayFile   = "data/v1/cia/days/2026/10/01.json"
	releaseID = "data/v1/cia/releases/"
)

// Each way a reader might doubt the CIA record is caught, and named.
func TestCIATamperingIsCaught(t *testing.T) {
	for _, c := range []struct {
		name   string
		tamper func(t *testing.T, dir string)
		expect string // a substring of the failures
	}{
		{"run record edited (its successor no longer matches)", func(t *testing.T, dir string) {
			runRecord(t, dir, slowSlot, func(r *record.CIARun) { r.FinishedAt = "2026-10-01T11:05:30Z" })
		}, "hashes to"},
		{"run record deleted", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, slowSlot)); err != nil {
				t.Fatal(err)
			}
		}, "but the record before it is"},
		{"level that its code does not allow", func(t *testing.T, dir string) {
			runRecord(t, dir, slowSlot, func(r *record.CIARun) {
				s := r.Services["sign"]
				s.Availability.Checks[0].Healthz.Level = "ok"
				r.Services["sign"] = s
			})
		}, "must be warn, not ok"},
		{"dimension better than its worst check", func(t *testing.T, dir string) {
			runRecord(t, dir, slowSlot, func(r *record.CIARun) {
				s := r.Services["sign"]
				s.Availability.Level = "ok"
				r.Services["sign"] = s
			})
		}, "is not the worst of its checks"},
		{"code of another check", func(t *testing.T, dir string) {
			runRecord(t, dir, slowSlot, func(r *record.CIARun) {
				s := r.Services["sign"]
				s.Availability.Checks[0].Healthz.Code = "verified"
				r.Services["sign"] = s
			})
		}, "is not a code of healthz"},
		{"checks out of order", func(t *testing.T, dir string) {
			runRecord(t, dir, slowSlot, func(r *record.CIARun) {
				s := r.Services["status"]
				c := s.Availability.Checks
				c[1], c[2] = c[2], c[1]
				r.Services["status"] = s
			})
		}, "sorted by name"},
		{"a record under the name of another slot (duplicate slot)", func(t *testing.T, dir string) {
			data, err := os.ReadFile(filepath.Join(dir, slowSlot))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "data/v1/cia/runs/2026/10/01/0505Z.json"), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "belongs at"},
		{"link to a witness record that does not exist", func(t *testing.T, dir string) {
			runRecord(t, dir, hourSlot, func(r *record.CIARun) {
				s := r.Services["status"]
				s.Integrity.Checks[1].Log.Record = ptr("data/v1/audit/witness/2026/10/01/999999Z.json")
				r.Services["status"] = s
			})
		}, "does not exist"},
		{"snapshot link of another snapshot", func(t *testing.T, dir string) {
			runRecord(t, dir, slowSlot, func(r *record.CIARun) { r.Incidents.Snapshot.SHA256 = strings.Repeat("0", 64) })
		}, "hashes to"},
		{"day file letter changed without its span", func(t *testing.T, dir string) {
			rewrite(t, dir, dayFile, "cia-day/v1", func(d *record.CIADay) {
				l := d.Services["vault"]
				l.Availability = strings.Replace(l.Availability, "f", "o", 1)
				d.Services["vault"] = l
			})
		}, "is not a fail slot"},
		{"day file outage erased, letters and spans together", func(t *testing.T, dir string) {
			rewrite(t, dir, dayFile, "cia-day/v1", func(d *record.CIADay) {
				l := d.Services["vault"]
				l.Availability = strings.ReplaceAll(l.Availability, "f", "o")
				d.Services["vault"] = l
				var kept []record.CIASpan
				for _, s := range d.Spans {
					if s.Service != "vault" || s.Dimension != "availability" || s.Level != "fail" {
						kept = append(kept, s)
					}
				}
				d.Spans = kept
			})
		}, "differs from the run records"},
		{"day file spans edited by hand", func(t *testing.T, dir string) {
			rewrite(t, dir, dayFile, "cia-day/v1", func(d *record.CIADay) { d.Spans[0].Code = "other" })
		}, "differs from the run records"},
		{"day file missing", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, dayFile)); err != nil {
				t.Fatal(err)
			}
		}, "no day file"},
		{"summary edited by hand", func(t *testing.T, dir string) {
			rewrite(t, dir, record.CIASummaryPath, "cia-summary/v1", func(s *record.CIASummary) {
				v := s.Services["vault"]
				v.Uptime.Up = v.Uptime.Measured
				s.Services["vault"] = v
			})
		}, "differs from the day files"},
		{"latest edited by hand", func(t *testing.T, dir string) {
			rewrite(t, dir, record.CIALatestPath, "cia-latest/v1", func(l *record.CIALatest) { l.Headline.Integrity = "ok" })
		}, "differs from the latest run record"},
		{"incidents view edited by hand", func(t *testing.T, dir string) {
			p := filepath.Join(dir, record.CIAIncidentsViewPath)
			data, _ := os.ReadFile(p)
			if err := os.WriteFile(p, []byte(strings.Replace(string(data), "medium", "low", 1)), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "differs from the snapshot and the events"},
		{"release manifest edited", func(t *testing.T, dir string) {
			p := latestVerdictDir(t, dir, "vault") + "/manifest.json"
			data, _ := os.ReadFile(p)
			if err := os.WriteFile(p, []byte(strings.Replace(string(data), "0.1.29", "0.1.30", 1)), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "hashes to"},
		{"verdict signed by another identity", func(t *testing.T, dir string) {
			p := latestVerdictDir(t, dir, "sign") + "/verdict.json"
			data, _ := os.ReadFile(p)
			if err := os.WriteFile(p, []byte(strings.Replace(string(data), "pipeline.yml@refs/heads/main", "other.yml@refs/heads/main", 1)), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "the pin is"},
		{"timestamp pins a different run record", func(t *testing.T, dir string) {
			runRecord(t, dir, hourSlot, func(r *record.CIARun) { r.FinishedAt = "2026-10-01T05:20:30Z" })
		}, "subject cia"},
		{"timings whose total is not the latency", func(t *testing.T, dir string) {
			runRecord(t, dir, slowSlot, func(r *record.CIARun) {
				s := r.Services["sign"]
				s.Availability.Checks[0].Healthz.Timings.TotalMs++
				r.Services["sign"] = s
			})
		}, "is not latencyMs"},
		{"a phase longer than the attempt", func(t *testing.T, dir string) {
			runRecord(t, dir, slowSlot, func(r *record.CIARun) {
				s := r.Services["sign"]
				h := s.Availability.Checks[0].Healthz
				h.Timings.FirstByteMs = ptr(h.Timings.TotalMs + 1)
				r.Services["sign"] = s
			})
		}, "longer than the attempt"},
		{"vantage that is not provider:region", func(t *testing.T, dir string) {
			runRecord(t, dir, slowSlot, func(r *record.CIARun) { r.Vantage = "Scaleway Paris" })
		}, "provider:region"},
		{"day file without latency", func(t *testing.T, dir string) {
			rewrite(t, dir, dayFile, "cia-day/v1", func(d *record.CIADay) {
				l := d.Services["vault"]
				l.Latency = nil
				d.Services["vault"] = l
			})
		}, "has no latency"},
		{"day file with another latency", func(t *testing.T, dir string) {
			rewrite(t, dir, dayFile, "cia-day/v1", func(d *record.CIADay) {
				l := d.Services["vault"]
				l.Latency.P95Ms = ptr(*l.Latency.P95Ms + 1)
				d.Services["vault"] = l
			})
		}, "does not follow from its slotsMs"},
		{"day file with the latency of another slot", func(t *testing.T, dir string) {
			rewrite(t, dir, dayFile, "cia-day/v1", func(d *record.CIADay) {
				l := d.Services["sign"].Latency
				l.SlotsMs[133] = ptr(*l.SlotsMs[133] + 1) // a slot that answered slowly, one millisecond off
				*l = *cia.DayLatency(l.SlotsMs)
			})
		}, "latency in slot 133"},
		{"day file counting a sample that does not exist", func(t *testing.T, dir string) {
			rewrite(t, dir, dayFile, "cia-day/v1", func(d *record.CIADay) {
				l := d.Services["vault"]
				l.Latency.Samples--
				d.Services["vault"] = l
			})
		}, "does not follow from its slotsMs"},
		{"summary without p95Ms", func(t *testing.T, dir string) {
			rewrite(t, dir, record.CIASummaryPath, "cia-summary/v1", func(s *record.CIASummary) {
				v := s.Services["vault"]
				v.P95Ms = nil
				s.Services["vault"] = v
			})
		}, "has no p95Ms"},
		{"summary p95Ms changed", func(t *testing.T, dir string) {
			rewrite(t, dir, record.CIASummaryPath, "cia-summary/v1", func(s *record.CIASummary) {
				s.Services["vault"].P95Ms[89] = ptr(1)
			})
		}, "differs from the day files"},
		{"stray file in the CIA layout", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "data/v1/cia/extra.json"), []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "no place"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, dir := generateExamples(t)
			c.tamper(t, dir)
			failed, _ := verifyAll(t, dir)
			if all := strings.Join(failed, "\n"); !strings.Contains(all, c.expect) {
				t.Errorf("not reported as %q; failures:\n%s", c.expect, all)
			}
		})
	}
}

func latestVerdictDir(t *testing.T, dir, service string) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, releaseID, service))
	if err != nil || len(entries) != 1 {
		t.Fatalf("release directories of %s: %v %v", service, entries, err)
	}
	return filepath.Join(dir, releaseID, service, entries[0].Name())
}
