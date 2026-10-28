package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

const (
	v2Slot      = "data/v1/cia/runs/2026/10/01/1355Z.json" // both witnesses measured, the vault is fine
	v2Regional  = "data/v1/cia/runs/2026/10/01/1405Z.json" // the vault cannot be reached from Latin America
	latamRecord = "data/v1/witnesses/latam/audit/witness/2026/10/01/102507Z.json"
)

// v2Edit decodes the cia-run/v2 record at path, lets change edit it and writes it
// back in the house encoding, the way the auditor would have written it.
func v2Edit(t *testing.T, dir, path string, change func(*record.CIARunV2)) {
	t.Helper()
	rewrite(t, dir, path, "cia-run/v2", change)
}

// resign signs the witness's measurement again with its example key, as the
// witness itself would have: the digest is the edited measurement's, the request
// the one the entry already names.
func resign(t *testing.T, r *record.CIARunV2, witness string) {
	t.Helper()
	c := newTestCIASim(t)
	e := r.Witnesses[witness]
	request := "none"
	if witness != record.WitnessEurope {
		for _, line := range strings.Split(*e.Note, "\n") {
			if v, ok := strings.CutPrefix(line, "request "); ok {
				request = v
			}
		}
	}
	n, err := signMeasurement(c.signers[witness], witness, r.Slot, request, *e.Measured)
	if err != nil {
		t.Fatal(err)
	}
	e.Note = &n
	r.Witnesses[witness] = e
}

func newTestCIASim(t *testing.T) *ciaSim {
	t.Helper()
	c, err := newCIASim(&writer{root: t.TempDir()}, filepath.Join("..", "..", "examples", "incidents"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func failures(t *testing.T, dir string) string {
	t.Helper()
	failed, _ := verifyAll(t, dir)
	return strings.Join(failed, "\n")
}

// Each way a reader might doubt what the second witness says is caught, and
// named (ARCH-V2 §8.6).
func TestV2TamperingIsCaught(t *testing.T) {
	for _, c := range []struct {
		name   string
		tamper func(t *testing.T, dir string)
		expect string // a substring of the failures
	}{
		{"a number of Latin America changed after it was signed", func(t *testing.T, dir string) {
			v2Edit(t, dir, v2Slot, func(r *record.CIARunV2) {
				r.Witnesses["latam"].Measured.Probes["vault"].Timings.TotalMs++
			})
		}, "changed after it was signed"},
		{"a number of Europe changed after it was signed", func(t *testing.T, dir string) {
			v2Edit(t, dir, v2Slot, func(r *record.CIARunV2) {
				r.Witnesses["europe"].Measured.Probes["vault"].Timings.TotalMs++
			})
		}, "changed after it was signed"},
		{"a number of Latin America changed and signed with Europe's key", func(t *testing.T, dir string) {
			v2Edit(t, dir, v2Slot, func(r *record.CIARunV2) {
				r.Witnesses["latam"].Measured.Probes["vault"].Timings.TotalMs++
				e := r.Witnesses["latam"]
				c := newTestCIASim(t)
				n, err := signMeasurement(c.signers["europe"], "latam", r.Slot, strings.Repeat("a", 64), *e.Measured)
				if err != nil {
					t.Fatal(err)
				}
				e.Note = &n
				r.Witnesses["latam"] = e
			})
		}, "does not verify"},
		{"the note of another slot", func(t *testing.T, dir string) {
			other := loadRun(t, dir, "2026-10-01T13:50").V2.Witnesses["latam"].Note
			v2Edit(t, dir, v2Slot, func(r *record.CIARunV2) {
				e := r.Witnesses["latam"]
				e.Note = other
				r.Witnesses["latam"] = e
			})
		}, "cannot be moved to another run"},
		{"a regional failure written as a failure", func(t *testing.T, dir string) {
			v2Edit(t, dir, v2Regional, func(r *record.CIARunV2) {
				svc := r.Services["vault"]
				svc.Availability = record.CIADimensionV2{Level: "fail", Checks: []record.CIACheckV2{{Healthz: &record.CombinedCheck{ID: "healthz", Level: "fail", Code: "timeout"}}}}
				r.Services["vault"] = svc
			})
		}, "combine to warn/regional"},
		{"a failure of both written as an amber regional one", func(t *testing.T, dir string) {
			v2Edit(t, dir, "data/v1/cia/runs/2026/10/01/1255Z.json", func(r *record.CIARunV2) {
				svc := r.Services["frontend"]
				svc.Availability = record.CIADimensionV2{Level: "warn", Checks: []record.CIACheckV2{{Healthz: &record.CombinedCheck{ID: "healthz", Level: "warn", Code: "regional", Error: new(string)}}}}
				r.Services["frontend"] = svc
			})
		}, "combine to fail/http-status"},
		{"Latin America measured, with no measurement", func(t *testing.T, dir string) {
			v2Edit(t, dir, v2Slot, func(r *record.CIARunV2) {
				e := r.Witnesses["latam"]
				e.Measured = nil
				r.Witnesses["latam"] = e
			})
		}, "has its note and its measurement"},
		{"Latin America missing without a reason", func(t *testing.T, dir string) {
			v2Edit(t, dir, v2Slot, func(r *record.CIARunV2) {
				r.Witnesses["latam"] = record.WitnessEntry{Status: "unavailable"}
			})
		}, "has a reason"},
		{"Europe's entry removed", func(t *testing.T, dir string) {
			v2Edit(t, dir, v2Slot, func(r *record.CIARunV2) { delete(r.Witnesses, "europe") })
		}, "writes the record"},
		{"a witness record of Latin America moved into the primary's namespace", func(t *testing.T, dir string) {
			data, err := os.ReadFile(filepath.Join(dir, latamRecord))
			if err != nil {
				t.Fatal(err)
			}
			to := filepath.Join(dir, "data/v1/audit/witness/2026/10/01/102507Z.json")
			if err := os.WriteFile(to, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "witness key"},
		{"a witness record of Latin America in the namespace of Europe", func(t *testing.T, dir string) {
			data, _ := os.ReadFile(filepath.Join(dir, latamRecord))
			to := filepath.Join(dir, "data/v1/witnesses/europe/audit/witness/2026/10/01/102507Z.json")
			if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(to, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "no place"},
		{"a witness record of Latin America deleted from its chain", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, latamRecord)); err != nil {
				t.Fatal(err)
			}
		}, "does not exist"},
		{"a measurement that names a record of the other witness", func(t *testing.T, dir string) {
			v2Edit(t, dir, v2Slot, func(r *record.CIARunV2) {
				l := r.Witnesses["latam"].Measured.Logs["audit"]
				l.Record = r.Witnesses["europe"].Measured.Logs["audit"].Record
				r.Witnesses["latam"].Measured.Logs["audit"] = l
				resign(t, r, "latam")
			})
		}, "is not a witness record of latam"},
		{"the second witness reports the published history changed, and no change event says so", func(t *testing.T, dir string) {
			v2Edit(t, dir, v2Slot, func(r *record.CIARunV2) {
				r.Witnesses["latam"].Measured.Peer.Verdict = "mismatch"
				resign(t, r, "latam")
			})
		}, "is missing: a change the records show is not listed"},
		{"the second witness saw the primary's record as other bytes", func(t *testing.T, dir string) {
			v2Edit(t, dir, v2Slot, func(r *record.CIARunV2) {
				r.Witnesses["latam"].Measured.Peer.SHA256 = new(string)
				*r.Witnesses["latam"].Measured.Peer.SHA256 = strings.Repeat("0", 64)
				resign(t, r, "latam")
			})
		}, "but the file hashes to"},
		{"a split view with no finding", func(t *testing.T, dir string) {
			v2Edit(t, dir, "data/v1/cia/runs/2026/10/01/1330Z.json", func(r *record.CIARunV2) { // both read signs at size 9236
				l := r.Witnesses["latam"].Measured.Logs["signs"]
				root := strings.Repeat("A", 43) + "="
				l.Root = &root
				size := *r.Witnesses["europe"].Measured.Logs["signs"].Size
				l.Size = &size
				r.Witnesses["latam"].Measured.Logs["signs"] = l
				resign(t, r, "latam")
			})
		}, "split view"},
		{"a probe that failed at the transport while the control probe did too, recorded as an outage", func(t *testing.T, dir string) {
			v2Edit(t, dir, v2Slot, func(r *record.CIARunV2) {
				m := r.Witnesses["latam"].Measured
				m.Control.OK = false
				for id, p := range m.Probes {
					p.Code, p.Class, p.Attempts, p.RetriedAfter, p.HTTPStatus = "connect-error", new(string), 2, new(string), nil
					*p.Class, *p.RetriedAfter = "connect", "connect"
					m.Probes[id] = p
				}
				resign(t, r, "latam")
			})
		}, "which is a vantage failure"},
		{"the day file's region of Latin America edited", func(t *testing.T, dir string) {
			rewrite(t, dir, dayFile, "cia-day/v1", func(d *record.CIADay) {
				s := d.Services["vault"]
				reg := s.Regions["latam"]
				reg.Availability = strings.Replace(reg.Availability, "f", "o", 1)
				s.Regions["latam"] = reg
				d.Services["vault"] = s
			})
		}, "region latam"},
		{"the day file's region without the regions it should have", func(t *testing.T, dir string) {
			rewrite(t, dir, dayFile, "cia-day/v1", func(d *record.CIADay) {
				s := d.Services["vault"]
				s.Regions = nil
				d.Services["vault"] = s
			})
		}, "has no region"},
		{"the summary's region edited", func(t *testing.T, dir string) {
			rewrite(t, dir, record.CIASummaryPath, "cia-summary/v1", func(s *record.CIASummary) {
				v := s.Services["vault"]
				r := v.Regions["latam"]
				r.Uptime.Up++
				v.Regions["latam"] = r
				s.Services["vault"] = v
			})
		}, "differs from the day files"},
		{"the latest view's witness status edited", func(t *testing.T, dir string) {
			rewrite(t, dir, record.CIALatestPath, "cia-latest/v1", func(l *record.CIALatest) {
				w := l.Witnesses["latam"]
				w.Status = "unavailable"
				l.Witnesses["latam"] = w
			})
		}, "differs from the latest run record"},
		{"a change event of the witnesses removed", func(t *testing.T, dir string) {
			rewrite(t, dir, record.CIAChangesPath, "cia-changes/v1", func(c *record.CIAChanges) {
				var kept []record.CIAChange
				for _, e := range c.Events {
					if e.Kind != "witness-unavailable" {
						kept = append(kept, e)
					}
				}
				c.Events = kept
			})
		}, "is missing"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, dir := generateExamples(t)
			c.tamper(t, dir)
			if all := failures(t, dir); !strings.Contains(all, c.expect) {
				t.Errorf("not reported as %q; failures:\n%.3000s", c.expect, all)
			}
		})
	}
}
