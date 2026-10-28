package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// loadRun reads the run record of a slot ("2026-10-01T14:20") of the examples.
func loadRun(t *testing.T, dir, slot string) *record.CIARun {
	t.Helper()
	at, err := time.Parse("2006-01-02T15:04", slot)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, record.CIARunPath(at)))
	if err != nil {
		t.Fatal(err)
	}
	run, err := record.DecodeRun(data)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func readView[T any](t *testing.T, dir, path, schema string) T {
	t.Helper()
	var v T
	data, err := os.ReadFile(filepath.Join(dir, path))
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Decode(data, schema, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// The history is one chain of run records through the change of version: v1
// until 10:00, v2 from then on, each linking the bytes of the one before.
func TestTheChainCrossesTheVersionBoundary(t *testing.T) {
	_, dir := generateExamples(t)
	before, first := loadRun(t, dir, "2026-10-01T09:55"), loadRun(t, dir, "2026-10-01T10:00")
	if before.V2 != nil || first.V2 == nil || first.Prev == nil || first.Prev.Record != record.CIARunPath(mustTime("2026-10-01T09:55:00Z")) {
		t.Fatalf("v1 until 09:55 and v2 from 10:00: %v %v %+v", before.V2 != nil, first.V2 != nil, first.Prev)
	}
}

// Every v2 record is in the house encoding: decoding it strictly and encoding it
// again gives its own bytes, so a person reading it on GitHub and a program
// reading it see the same thing.
func TestEveryV2RecordIsInTheHouseEncoding(t *testing.T) {
	_, dir := generateExamples(t)
	n := 0
	err := filepath.WalkDir(filepath.Join(dir, "data/v1/cia/runs"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, _ := os.ReadFile(p)
		run, err := record.DecodeRun(data)
		if err != nil || run.V2 == nil {
			return err
		}
		n++
		if out, _ := record.Encode(run.V2); !bytes.Equal(out, data) {
			t.Errorf("%s is not in the house encoding", p)
		}
		return nil
	})
	if err != nil || n != 53 {
		t.Errorf("%d v2 records, %v", n, err)
	}
}

// What the page needs to show is in the examples: each situation the scenario
// scripts is in the records, the views and the change events.
func TestTheScriptedSituationsAreInTheExamples(t *testing.T) {
	_, dir := generateExamples(t)
	probe := func(slot, witness, service string) string {
		m := loadRun(t, dir, slot).V2.Witnesses[witness].Measured
		if m == nil {
			return "unavailable"
		}
		return m.Probes[service].Code
	}
	level := func(slot, service string) string {
		s := loadRun(t, dir, slot).Services[service].Availability
		return s.Level + "/" + s.Checks[0].Code()
	}
	reason := func(slot string) string {
		e := loadRun(t, dir, slot).V2.Witnesses["latam"]
		if e.Reason == nil {
			return e.Status
		}
		return *e.Reason
	}
	for _, c := range []struct {
		name, got, want string
	}{
		{"the secondary is silent for five runs: timeouts and an unreachable", strings.Join([]string{reason("2026-10-01T11:25"), reason("2026-10-01T11:30"), reason("2026-10-01T11:35"), reason("2026-10-01T11:40"), reason("2026-10-01T11:45"), reason("2026-10-01T11:50")}, " "),
			"timeout timeout unreachable timeout timeout ok"},
		{"the vault cannot be reached from Latin America: amber, regional", level("2026-10-01T14:05", "vault"), "warn/regional"},
		{"Europe reaches it", probe("2026-10-01T14:05", "europe", "vault"), "ok"},
		{"and Latin America does not", probe("2026-10-01T14:05", "latam", "vault"), "timeout"},
		{"both fail: red", level("2026-10-01T12:55", "frontend"), "fail/http-status"},
		{"both saw it", probe("2026-10-01T12:55", "latam", "frontend"), "http-status"},
		{"Europe alone confirms a failure, the secondary silent: red", level("2026-10-01T11:30", "sign"), "fail/connect-error"},
		{"a slow service is amber from both", level("2026-10-01T11:05", "sign"), "warn/slow"},
		{"Europe's own network failed: Latin America decides", level("2026-10-01T13:15", "frontend"), "ok/ok"},
		{"and Europe measured nothing", probe("2026-10-01T13:15", "europe", "frontend"), "vantage"},
		{"a probe the edge challenged", probe("2026-10-01T13:20", "latam", "sign"), "challenged"},
		{"which says nothing about the service", level("2026-10-01T13:20", "sign"), "ok/ok"},
		{"a cold start: the first services were measured", probe("2026-10-01T13:25", "latam", "frontend"), "ok"},
		{"and the last were not", probe("2026-10-01T13:25", "latam", "vault"), "vantage"},
		{"an answer that did not verify", reason("2026-10-01T13:10"), "signature"},
		{"an answer lost on the way", reason("2026-10-01T12:20"), "timeout"},
	} {
		if c.got != c.want {
			t.Errorf("%s: %q, want %q", c.name, c.got, c.want)
		}
	}

	peers := map[string]string{}
	for _, slot := range []string{"2026-10-01T10:00", "2026-10-01T10:05", "2026-10-01T11:50", "2026-10-01T11:55", "2026-10-01T12:25"} {
		peers[slot] = loadRun(t, dir, slot).V2.Witnesses["latam"].Measured.Peer.Verdict
	}
	want := map[string]string{"2026-10-01T10:00": "gap", "2026-10-01T10:05": "ok", "2026-10-01T11:50": "gap", "2026-10-01T11:55": "ok", "2026-10-01T12:25": "ok"}
	for slot, v := range want {
		if peers[slot] != v {
			t.Errorf("peer verdict at %s is %s, want %s: it is a gap on the first run and after an absence", slot, peers[slot], v)
		}
	}

	kinds := map[string]string{}
	for _, e := range readView[record.CIAChanges](t, dir, record.CIAChangesPath, "cia-changes/v1").Events {
		if strings.HasPrefix(e.Kind, "witness-") {
			kinds[e.ID] = e.Kind
		}
	}
	for id, kind := range map[string]string{
		"202610011135-witness-latam-unavailable":  "witness-unavailable",
		"202610011155-witness-latam-restored":     "witness-restored",
		"202610011310-witness-latam-disagreement": "witness-disagreement", // the answer that did not verify
		"202610011335-log-signs-disagreement":     "witness-disagreement", // a split view: both read size 9236, with two roots
	} {
		if kinds[id] != kind {
			t.Errorf("change event %s is %q, want %s; the witness events are %v", id, kinds[id], kind, kinds)
		}
	}
	if len(kinds) != 4 {
		t.Errorf("%d witness events, want 4: %v", len(kinds), kinds)
	}

	day := readView[record.CIADay](t, dir, dayFile, "cia-day/v1")
	vault := day.Services["vault"].Regions
	if got := vault["latam"].Availability[168:174]; got != "fffff-" {
		t.Errorf("Latin America's vault, 14:00 to 14:20: %q", got)
	}
	if got := vault["europe"].Availability[168:173]; got != "ooooo" {
		t.Errorf("Europe's vault at the same time: %q", got)
	}
	if got := day.Services["vault"].Availability[168:173]; got != "wwwww" {
		t.Errorf("the vault's combined availability then: %q", got)
	}
	if day.Services["frontend"].Regions["latam"].Availability[100] != '-' || day.Services["frontend"].Regions["europe"].Availability[100] != 'o' {
		t.Error("before the change of version only the primary witness has measured")
	}

	latest := readView[record.CIALatest](t, dir, record.CIALatestPath, "cia-latest/v1")
	if r := latest.Services["vault"].Availability.Regions["latam"]; r.Level != "fail" || r.Code != "timeout" || r.LatencyMs != nil || r.Since != "2026-10-01T14:00:00Z" {
		t.Errorf("latest vault in Latin America: %+v", r)
	}
	// The answer of 13:10 did not verify, so the sequence of answers that did begins at 13:15.
	if w := latest.Witnesses["latam"]; w.Status != "ok" || w.Since != "2026-10-01T13:15:00Z" || w.Vantage == nil || *w.Vantage != "oci:sa-saopaulo-1" {
		t.Errorf("latest witness latam: %+v", w)
	}
	// Europe's own network failed at 13:15, so its probe of the vault has been ok only since 13:20.
	if r := latest.Services["vault"].Availability.Regions["europe"]; r.Level != "ok" || r.Since != "2026-10-01T13:20:00Z" {
		t.Errorf("latest vault in Europe: %+v", r)
	}
}

// The second witness has its own chain of records, in its own namespace, with
// its own previous links; nothing about it enters the primary's summaries.
func TestTheSecondWitnessHasItsOwnChain(t *testing.T) {
	_, dir := generateExamples(t)
	state := readView[record.State](t, dir, "data/v1/state.json", "state/v1")
	for log, l := range state.Logs {
		if strings.Contains(l.Record, "witnesses/") {
			t.Errorf("state.json lists the second witness's record of %s: %s", log, l.Record)
		}
	}
	for _, log := range []string{"audit", "signs"} {
		paths, _ := filepath.Glob(filepath.Join(dir, "data/v1/witnesses/latam", log, "witness/2026/10/01/*.json"))
		if len(paths) < 2 {
			t.Fatalf("%s: %d records of the second witness", log, len(paths))
		}
		var prev string
		for i, p := range paths {
			var w record.Witness
			data, _ := os.ReadFile(p)
			if err := record.Decode(data, "witness/v1", &w); err != nil {
				t.Fatal(err)
			}
			rel, _ := filepath.Rel(dir, p)
			switch {
			case i == 0 && w.Previous != nil:
				t.Errorf("%s: the first record of a chain has no previous", rel)
			case i > 0 && (w.Previous == nil || w.Previous.Record != prev):
				t.Errorf("%s links %+v, the record before it is %s", rel, w.Previous, prev)
			}
			prev = filepath.ToSlash(rel)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "keys/witness/latam.vkey")); err != nil {
		t.Error("the second witness's key is not among the example keys")
	}
}
