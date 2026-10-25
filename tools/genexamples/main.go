// Command genexamples writes the example data set under examples/: two logs
// with realistic growth, witness records every time a tree grows, an hourly
// RFC 3161 timestamp chain (with one provider fallback and one hour with no
// token), and one equivocation finding, all signed with example keys.
//
// The page loads it with ?data=examples. Nothing here is a real record:
// every name uses the reserved .example domain and every key comes from a
// public seed (keys.go). Run it from the repository root:
//
//	go run ./tools/genexamples
//
// The output is deterministic, so a regenerated data set only differs where
// the code changed.
package main

import (
	"encoding/asn1"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cosig"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

var (
	start = time.Date(2026, 9, 30, 11, 0, 0, 0, time.UTC)
	end   = time.Date(2026, 10, 1, 14, 20, 0, 0, time.UTC)
)

func main() {
	out := flag.String("out", "examples", "directory to write data/ and keys/ into")
	flag.Parse()
	if _, err := generate(*out); err != nil {
		fmt.Fprintln(os.Stderr, "genexamples:", err)
		os.Exit(1)
	}
}

// generate writes the data set and returns the simulation, whose trees the
// tests serve as logs.
func generate(out string) (*sim, error) {
	s, err := simulate(out)
	if err != nil {
		return nil, err
	}
	return s, s.writeSummaries()
}

func simulate(out string) (*sim, error) {
	for _, dir := range []string{"data", "keys"} {
		if err := os.RemoveAll(filepath.Join(out, dir)); err != nil {
			return nil, err
		}
	}
	w := &writer{root: out}

	s := &sim{
		w:          w,
		rng:        rand.New(rand.NewPCG(2026, 10)),
		witnessKey: witnessKey("witness.example/auditor/v1"),
		idx:        map[string]*record.Index{},
		tsaFails: map[time.Time]int{
			time.Date(2026, 9, 30, 18, 0, 0, 0, time.UTC): 1, // primary down, backup answers
			time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC):  2, // both down: a visible gap
		},
	}
	var err error
	if s.witnessV, err = cosig.NewVerifier(cosig.VKey("witness.example/auditor/v1", s.witnessKey.Public().(ed25519PublicKey))); err != nil {
		return nil, err
	}
	if err := w.text("keys/witness/auditor.vkey", s.witnessV.VKey()+"\n"); err != nil {
		return nil, err
	}

	for _, spec := range []struct {
		name    string
		initial int
		grow    func(time.Time, *rand.Rand) int
		equiv   time.Time
	}{
		{"audit", 182_340, auditGrowth, time.Time{}},
		{"signs", 9_120, signsGrowth, time.Date(2026, 10, 1, 13, 35, 0, 0, time.UTC)},
	} {
		origin := "transparency.example/" + spec.name + "/v1"
		signer, vkey, err := logSigner(origin)
		if err != nil {
			return nil, err
		}
		l := &logSim{name: spec.name, origin: origin, url: "https://" + origin + "/", signer: signer, vkey: vkey,
			grow: spec.grow, equivocateAt: spec.equiv}
		if l.verifier, err = noteVerifier(vkey); err != nil {
			return nil, err
		}
		for i := range spec.initial {
			l.tree.AppendLeaf(fmt.Appendf(nil, "%s history %d", spec.name, i))
		}
		if err := w.text("keys/logs/"+spec.name+".vkey", vkey+"\n"); err != nil {
			return nil, err
		}
		s.logs = append(s.logs, l)
	}

	for i, spec := range []struct{ provider, url, label string }{
		{"example-tsa", "https://tsa.example/tsr", "Example TSA"},
		{"example-tsa-backup", "https://backup-tsa.example/tsr", "Example Backup TSA"},
	} {
		tsa, err := newExampleTSA(spec.provider, spec.url, spec.label, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1, i + 1})
		if err != nil {
			return nil, err
		}
		if err := w.raw("keys/tsa/"+spec.provider+".pem", tsa.chainPEM()); err != nil {
			return nil, err
		}
		s.tsas = append(s.tsas, tsa)
	}

	return s, s.run(start, end)
}

// writeSummaries writes what the witness rewrites on every commit: the
// state, the summary the page reads first, and the month indexes.
func (s *sim) writeSummaries() error {
	updated := record.FormatTime(s.lastRun)
	state := record.State{Schema: "state/v1", UpdatedAt: updated, Logs: map[string]record.StateLog{}, Timestamp: s.lastHour}
	latest := record.Latest{
		Schema: "latest/v1", UpdatedAt: updated, Logs: map[string]record.LatestLog{},
		Witness:   record.Cosignature{Name: s.witnessV.Name(), KeyHash: fmt.Sprintf("%08x", s.witnessV.KeyHash())},
		Timestamp: s.latestTS, Findings: []record.FindingSummary{}, Months: []string{},
	}
	for _, l := range s.logs {
		if l.last == nil {
			continue
		}
		rec := l.last.rec
		state.Logs[l.name] = record.StateLog{Origin: l.origin, Size: rec.Checkpoint.Size, Root: rec.Checkpoint.Root, Record: l.last.path, WitnessedAt: rec.WitnessedAt}
		var prev *uint64
		if rec.Previous != nil {
			prev = &rec.Previous.Size
		}
		latest.Logs[l.name] = record.LatestLog{Origin: l.origin, URL: l.url, CheckedAt: updated, Size: rec.Checkpoint.Size,
			Root: rec.Checkpoint.Root, WitnessedAt: rec.WitnessedAt, Record: l.last.path, PreviousSize: prev}
	}
	for i := len(s.findings) - 1; i >= 0; i-- {
		latest.Findings = append(latest.Findings, s.findings[i])
	}
	for m := range s.idx {
		latest.Months = append(latest.Months, m)
	}
	slices.Sort(latest.Months)
	slices.Reverse(latest.Months)

	for _, m := range latest.Months {
		ix := s.idx[m]
		ix.UpdatedAt = lastActivity(ix)
		t, _ := time.Parse("2006-01", m)
		if _, err := s.w.json(record.IndexPath(t), ix); err != nil {
			return err
		}
	}
	if _, err := s.w.json("data/v1/state.json", state); err != nil {
		return err
	}
	_, err := s.w.json("data/v1/latest.json", latest)
	return err
}

// lastActivity is when the month index was last written: its newest entry.
func lastActivity(ix *record.Index) string {
	newest := ""
	for _, entries := range ix.Logs {
		for _, e := range entries {
			newest = max(newest, e.At)
		}
	}
	for _, t := range ix.Timestamps {
		if t.GenTime != nil {
			newest = max(newest, *t.GenTime)
		}
		newest = max(newest, t.Hour)
	}
	for _, f := range ix.Findings {
		newest = max(newest, f.DetectedAt)
	}
	return newest
}

// auditGrowth: the audit trail grows in most five-minute windows of the
// Brazilian working day (11:00-23:00 UTC) and rarely at night.
func auditGrowth(t time.Time, r *rand.Rand) int {
	if h := t.Hour(); h >= 11 && h < 23 {
		if r.Float64() < 0.85 {
			return 5 + r.IntN(70)
		}
		return 0
	}
	if r.Float64() < 0.2 {
		return 1 + r.IntN(6)
	}
	return 0
}

// signsGrowth: signatures are rarer, a few per hour in the working day.
func signsGrowth(t time.Time, r *rand.Rand) int {
	if h := t.Hour(); h >= 11 && h < 23 {
		if r.Float64() < 0.3 {
			return 1 + r.IntN(4)
		}
		return 0
	}
	if r.Float64() < 0.03 {
		return 1
	}
	return 0
}
