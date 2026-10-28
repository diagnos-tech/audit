package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
