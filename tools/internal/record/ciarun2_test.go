package record

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// run2 is a small cia-run/v2 record in the house encoding (testdata/run-v2.json, the golden file):
// the primary witness measured, the secondary did not answer.
var run2 = mustRead("testdata/run-v2.json")

func mustRead(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func TestDecodeRunV2RoundTripsAndProjects(t *testing.T) {
	r, err := DecodeRun([]byte(run2))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Encode(r.V2)
	if err != nil || string(out) != run2 {
		t.Errorf("a decoded record does not encode to its own bytes (%v):\n%s", err, out)
	}
	if r.V2 == nil || r.Schema != "cia-run/v2" || r.Slot != "2026-10-01T14:20:00Z" {
		t.Fatalf("projection %+v", r)
	}
	h := r.Services["vault"].Availability.Checks[0].Healthz
	if h == nil || h.LatencyMs == nil || *h.LatencyMs != 91 {
		t.Errorf("the projected healthz check carries the primary witness's latency: %+v", h)
	}
	if got := r.V2.Witnesses["europe"].MeasuredRaw; !bytes.HasPrefix(got, []byte("{")) || !strings.Contains(string(got), `"probes"`) {
		t.Errorf("the raw measurement is kept: %.40s", got)
	}
	if r.V2.PrimaryLatency("nothing") != nil {
		t.Error("a latency for a service nobody measured")
	}
}

func TestDecodeRunIsStrict(t *testing.T) {
	v1 := `{"schema":"cia-run/v1","slot":"2026-10-01T14:20:00Z","startedAt":"2026-10-01T14:20:01Z","finishedAt":"2026-10-01T14:20:09Z","prev":null,` +
		`"incidents":{"source":"none","commit":null,"readAt":null,"snapshot":null},"services":{}}`
	for _, c := range []struct {
		name string
		in   string
		want string // "" = accepted
	}{
		{"v1", v1, ""},
		{"v2", run2, ""},
		{"another schema", strings.Replace(run2, "cia-run/v2", "cia-run/v3", 1), "want cia-run/v1 or cia-run/v2"},
		{"no schema", `{}`, "want cia-run/v1 or cia-run/v2"},
		{"not json", `{`, "unexpected end"},
		{"an unknown field of the run", strings.Replace(run2, `"prev": null,`, `"prev": null, "extra": 1,`, 1), "unknown field"},
		{"an unknown field of an entry", strings.Replace(run2, `"reason": "timeout",`, `"reason": "timeout", "extra": 1,`, 1), "unknown field"},
		{"an unknown field of the measurement", strings.Replace(run2, `"vantage": "scaleway:fr-par",`, `"vantage": "scaleway:fr-par", "extra": 1,`, 1), "unknown field"},
		{"an unknown field of a probe", strings.Replace(run2, `"class": null,`, `"class": null, "extra": 1,`, 1), "unknown field"},
		{"a healthz check with the fields of v1", strings.Replace(run2, `"code": "ok",
            "error": null
          }
        ]
      },
      "integrity"`, `"code": "ok", "attempts": 1,
            "error": null
          }
        ]
      },
      "integrity"`, 1), "unknown field"},
		{"a check of a kind that does not exist", strings.Replace(run2, `"id": "healthz"`, `"id": "magic"`, 1), "unknown check id"},
		{"trailing data", run2 + "{}", "after top-level value"},
		{"a v2 record claiming to be v1", strings.Replace(run2, "cia-run/v2", "cia-run/v1", 1), "unknown field"},
	} {
		_, err := DecodeRun([]byte(c.in))
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

func FuzzDecodeRun(f *testing.F) {
	f.Add([]byte(run2))
	f.Add([]byte(`{"schema":"cia-run/v1"}`))
	f.Add([]byte(`{"schema":"cia-run/v2","witnesses":{"europe":{"status":"ok","measured":null}}}`))
	f.Add([]byte(`{"schema":"cia-run/v2","services":{"a":{"availability":{"level":"ok","checks":[{"id":"healthz"}]}}}}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := DecodeRun(data)
		if err != nil || r.V2 == nil {
			return
		}
		// What decodes encodes to something that decodes to the same record.
		out, err := Encode(r.V2)
		if err != nil {
			t.Fatalf("a decoded record cannot be encoded: %v", err)
		}
		again, err := DecodeRun(out)
		if err != nil {
			t.Fatalf("a re-encoded record does not decode: %v", err)
		}
		if a, b := mustMarshal(t, r.V2), mustMarshal(t, again.V2); !bytes.Equal(a, b) {
			t.Errorf("round trip changed the record:\n%s\n%s", a, b)
		}
	})
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWitnessOf(t *testing.T) {
	for _, c := range []struct {
		path    string
		witness string
		log     string
		ok      bool
	}{
		{"data/v1/audit/witness/2026/10/01/142005Z.json", "europe", "audit", true},
		{"data/v1/signs/findings/2026/10/01/133507Z.json", "europe", "signs", true},
		{"data/v1/witnesses/latam/audit/witness/2026/10/01/142007Z.json", "latam", "audit", true},
		{"data/v1/witnesses/latam/signs/findings/2026/10/01/133509Z.json", "latam", "signs", true},
		{"data/v1/witnesses/europe/audit/witness/2026/10/01/142005Z.json", "", "", false}, // the primary has no namespace
		{"data/v1/witnesses/witness/2026/10/01/142005Z.json", "", "", false},              // a log called like the directory
		{"data/v1/cia/witness/2026/10/01/142005Z.json", "", "", false},
		{"data/v1/index/witness/2026/10/01/142005Z.json", "", "", false},
		{"data/v1/witnesses/l/audit/witness/2026/10/01/142005Z.json", "", "", false},
		{"data/v1/witnesses/latam/extra/audit/witness/2026/10/01/142005Z.json", "", "", false},
		{"data/v1/audit/witness/2026/10/01/142005.json", "", "", false},
	} {
		w, l, ok := WitnessOf(c.path)
		if w != c.witness || l != c.log || ok != c.ok {
			t.Errorf("WitnessOf(%s) = %q %q %v", c.path, w, l, ok)
		}
		kind := Kind(c.path)
		if c.ok && !strings.HasPrefix(c.path, "data/v1/") || (kind == "witness" || kind == "finding") != c.ok {
			t.Errorf("Kind(%s) = %q", c.path, kind)
		}
	}
}

func TestEncodeCompactIsOneLine(t *testing.T) {
	out, err := EncodeCompact(map[string]any{"b": []int{1, 2}, "a": "<x & y>"})
	if err != nil || string(out) != `{"a":"<x & y>","b":[1,2]}`+"\n" {
		t.Errorf("%q %v", out, err)
	}
}

func TestErrorCounts(t *testing.T) {
	var e ErrorCounts
	for _, class := range ErrorClasses {
		if !e.Add(class) {
			t.Errorf("class %s is not counted", class)
		}
	}
	if e.Add("slow") || e.Total() != len(ErrorClasses) {
		t.Errorf("%+v", e)
	}
	if b, _ := json.Marshal(e); !strings.Contains(string(b), `"http-5xx":1`) {
		t.Errorf("%s", b)
	}
}

func TestSucceededCodes(t *testing.T) {
	for code, want := range map[string]bool{"ok": true, "retried": true, "slow": true, "tls-expiring": true,
		"timeout": false, "challenged": false, "vantage": false, "regional": false, "": false} {
		if Succeeded(code) != want {
			t.Errorf("Succeeded(%q) = %v", code, !want)
		}
	}
}
