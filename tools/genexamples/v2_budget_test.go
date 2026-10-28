package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// The cosignatures are reproducible: the line in a record is the one the C2SP
// cosignature/v1 format gives for the public example seed, computed here from
// the specification with nothing of the generator in between. Ed25519 signs
// deterministically, so a regenerated data set repeats it byte for byte.
func TestCosignaturesAreReproducibleFromTheSpecification(t *testing.T) {
	_, dir := generateExamples(t)
	for _, c := range []struct{ glob, key string }{
		{"data/v1/audit/witness/2026/09/30/110005Z.json", "witness.example/auditor/v1"},
		{"data/v1/audit/witness/2026/10/01/12*.json", "witness.example/auditor/v1"},
		{"data/v1/witnesses/latam/audit/witness/2026/10/01/10*.json", latamName},
		{"data/v1/witnesses/latam/signs/witness/2026/10/01/12*.json", latamName},
	} {
		paths, _ := filepath.Glob(filepath.Join(dir, c.glob))
		if len(paths) == 0 {
			t.Fatalf("no record matches %s", c.glob)
		}
		for _, p := range paths {
			data, _ := os.ReadFile(p)
			var w record.Witness
			if err := record.Decode(data, "witness/v1", &w); err != nil {
				t.Fatal(err)
			}
			body, _, _ := strings.Cut(w.Checkpoint.Note, "\n\n")
			body += "\n"
			at, _ := record.ParseTime(w.WitnessedAt)
			priv := ed25519.NewKeyFromSeed(seed("witness key: " + c.key))
			pub := priv.Public().(ed25519.PublicKey)
			hash := sha256.Sum256(append([]byte(c.key+"\n\x04"), pub...))
			sig := ed25519.Sign(priv, []byte(fmt.Sprintf("cosignature/v1\ntime %d\n%s", at.Unix(), body)))
			blob := append(append(hash[:4:4], binary.BigEndian.AppendUint64(nil, uint64(at.Unix()))...), sig...)
			want := "\u2014 " + c.key + " " + base64.StdEncoding.EncodeToString(blob) + "\n"
			if !strings.HasSuffix(w.Checkpoint.Note, want) {
				t.Errorf("%s: the cosignature line is not the one the specification gives:\n%s\nwant %s", p, w.Checkpoint.Note, want)
			}
		}
	}
}

// Sizes the contract promises (ARCH-V2 §8.5): a run record of four services seen
// by two witnesses is at most 10 KB compact and 3 KB compressed, a day 32 KB, the
// summary 28 KB and the latest view 5 KB. A page on a phone downloads these.
func TestSizeBudget(t *testing.T) {
	_, dir := generateExamples(t)
	check := func(path string, compact, gz int) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, path))
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := jsonUnmarshal(data, &v); err != nil {
			t.Fatal(err)
		}
		one, _ := record.EncodeCompact(v)
		var z bytes.Buffer
		w, _ := gzip.NewWriterLevel(&z, gzip.BestCompression)
		w.Write(one)
		w.Close()
		if len(one) > compact || (gz > 0 && z.Len() > gz) {
			t.Errorf("%s is %d bytes compact and %d gzipped, over its budget of %d and %d", path, len(one), z.Len(), compact, gz)
		}
	}
	for _, slot := range []string{"2026-10-01T10:00", "2026-10-01T12:55", "2026-10-01T13:25", "2026-10-01T14:20"} {
		check(record.CIARunPath(mustTime(slot[:16]+":00Z")), 10<<10, 3<<10)
	}
	check(dayFile, 32<<10, 0)
	check(record.CIASummaryPath, 28<<10, 0)
	check(record.CIALatestPath, 5<<10, 0)
}

func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }
