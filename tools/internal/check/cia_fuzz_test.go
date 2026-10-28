package check

import (
	"os"
	"path/filepath"
	"testing"
)

// Whatever bytes a run record is made of, checking it never panics: the verifier
// reads files it did not write, and a record that breaks a rule must be reported,
// not crash the check that would have reported it.
func FuzzCheckRunRecord(f *testing.F) {
	root := filepath.Join("..", "..", "..", "examples", "data", "v1", "cia", "runs", "2026")
	for _, name := range []string{"10/01/1355Z.json", "10/01/1135Z.json", "10/01/1315Z.json", "09/30/1925Z.json"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`{"schema":"cia-run/v2","slot":"2026-10-01T13:55:00Z","witnesses":{"europe":{"status":"ok","note":"x","measured":{"probes":{"a":{}}}}},"services":{"a":{"availability":{"level":"ok","checks":[{"id":"healthz"}]}}}}`))
	keys := newTestKey(f, "witness.example/auditor/v1", "fuzz")
	const path = "data/v1/cia/runs/2026/10/01/1355Z.json"
	f.Fuzz(func(t *testing.T, data []byte) {
		src := memSource{path: data}
		_, _, r := ciaRun(src, keysWith(map[string]testKey{"europe": keys}), newCIAReader(src), path)
		if r == nil {
			t.Fatal("no report")
		}
	})
}
