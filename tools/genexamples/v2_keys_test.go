package main

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/check"
	"github.com/diagnos-tech/audit/tools/internal/cosig"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// The key of the second witness is added later, by a person; until it is, the
// key is absent, which is not a failure: everything else about the records is
// checked, and the report says that the signatures were not.
func TestAbsentSecondWitnessKeyIsNotAFailure(t *testing.T) {
	_, dir := generateExamples(t)
	if err := os.Remove(filepath.Join(dir, "keys/witness/latam.vkey")); err != nil {
		t.Fatal(err)
	}
	failed, warned := verifyAll(t, dir)
	if len(failed) > 0 {
		t.Fatalf("an absent key failed the record:\n%s", strings.Join(failed, "\n"))
	}
	// The five reports every data set has, and the runs, witness records and findings that cannot be signature-checked.
	if warned <= 5+47 {
		t.Errorf("only %d reports with warnings: the unchecked signatures are not said", warned)
	}
}

// With the key absent a number that was changed still shows, because the lines of
// the note that carry the digest are still held to the record, and so does a
// note moved to another slot.
func TestAbsentKeyStillCatchesWhatNeedsNoKey(t *testing.T) {
	for name, tamper := range map[string]func(*record.CIARunV2){
		"changed after it was signed": func(r *record.CIARunV2) { r.Witnesses["latam"].Measured.Probes["vault"].Timings.TotalMs++ },
		"entry without its note":      func(r *record.CIARunV2) { e := r.Witnesses["latam"]; e.Note = nil; r.Witnesses["latam"] = e },
	} {
		t.Run(name, func(t *testing.T) {
			_, dir := generateExamples(t)
			v2Edit(t, dir, v2Slot, tamper)
			if err := os.Remove(filepath.Join(dir, "keys/witness/latam.vkey")); err != nil {
				t.Fatal(err)
			}
			if all := failures(t, dir); !strings.Contains(all, "changed after it was signed") && !strings.Contains(all, "has its note and its measurement") {
				t.Errorf("not reported:\n%.2000s", all)
			}
		})
	}
}

// A key file that is there but is not the key (or is another witness's) is
// never treated as absent.
func TestWrongSecondWitnessKeyFails(t *testing.T) {
	_, dir := generateExamples(t)
	europe, err := os.ReadFile(filepath.Join(dir, "keys/witness/auditor.vkey"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys/witness/latam.vkey"), europe, 0o644); err != nil {
		t.Fatal(err)
	}
	if all := failures(t, dir); !strings.Contains(all, "witness key") {
		t.Errorf("Europe's key under Latin America's name was accepted:\n%.2000s", all)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys/witness/latam.vkey"), []byte("pending\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if all := failures(t, dir); !strings.Contains(all, "malformed witness vkey") {
		t.Errorf("a placeholder text was treated as a key:\n%.2000s", all)
	}
}

// totals runs `verify all` over dir and counts what it reported.
func totals(t *testing.T, dir string) (files, warned, checks int, failed string) {
	t.Helper()
	src, err := record.Open(context.Background(), nil, dir)
	if err != nil {
		t.Fatal(err)
	}
	reports, err := check.AllWith(dir, src, check.NewKeyring(src, "keys/"), check.TimestampOptions{}, check.CIAOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var bad strings.Builder
	for _, r := range reports {
		checks += len(r.Results)
		switch r.Worst() {
		case check.Fail:
			r.Print(&bad, true)
		case check.Warn:
			warned++
		}
	}
	return len(reports), warned, checks, bad.String()
}

// A witness that rotates its key puts the new key first in its file and keeps
// the old one after it: every record already published, signed by the old key,
// verifies exactly as before. The keys of the new version are made here. What
// the verifier refuses in a key file is checked on single records, in
// tools/verify and in internal/check.
func TestKeyRotationKeepsPublishedRecordsVerifying(t *testing.T) {
	newKey := func(t *testing.T, name string) string {
		t.Helper()
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		return cosig.VKey(name, pub)
	}
	_, base := generateExamples(t)
	nFiles, warned, checks, failed := totals(t, base)
	if failed != "" {
		t.Fatalf("the examples as they are do not verify:\n%.2000s", failed)
	}
	read := func(dir, file string) string {
		data, err := os.ReadFile(filepath.Join(dir, "keys/witness", file))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	write := func(dir, file, text string) {
		if err := os.WriteFile(filepath.Join(dir, "keys/witness", file), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// The second witness alone (with blank lines around its keys), then both.
	for name, rotate := range map[string][]string{
		"the second witness": {"latam.vkey"},
		"both witnesses":     {"latam.vkey", "auditor.vkey"},
	} {
		_, dir := generateExamples(t)
		for _, file := range rotate {
			family := strings.TrimSuffix(strings.SplitN(read(dir, file), "+", 2)[0], "/v1")
			write(dir, file, "\n"+newKey(t, family+"/v2")+"\n\n"+read(dir, file)+"\n")
		}
		f, w, c, failed := totals(t, dir)
		if failed != "" || f != nFiles || w != warned || c != checks {
			t.Errorf("%s rotated: %d files, %d with warnings, %d checks (%.2000s), want %d, %d and %d with nothing failing", name, f, w, c, failed, nFiles, warned, checks)
		}
	}
}
