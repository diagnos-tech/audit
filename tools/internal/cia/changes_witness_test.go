package cia

import (
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// witnessRun is a run record of a service "vault" in which the primary witness
// measured and the secondary did as the state says: "up" (it measured), "down"
// (unavailable), "off" (not configured), "vantage" (its probes measured nothing),
// "signature" (its answer did not verify) or "mismatch" (it measured, and found
// the published history changed). "" leaves it out, as a cia-run/v1 record does.
func witnessRun(i int, latam string, extra ...func(*record.CIARunV2)) *record.CIARun {
	probe := func(code string) map[string]record.Probe {
		return map[string]record.Probe{"vault": {Code: code, Attempts: 1, Timings: &record.ProbeTimings{TotalMs: 90}}}
	}
	reason := func(s string) *string { return &s }
	v2 := &record.CIARunV2{Schema: "cia-run/v2", Slot: record.FormatTime(at(i)), Witnesses: map[string]record.WitnessEntry{
		"europe": {Status: "ok", Measured: &record.Measured{Probes: probe("ok"), Logs: map[string]record.WitnessLog{}}},
	}, Services: map[string]record.CIAServiceV2{"vault": {URL: "https://vault.example/",
		Availability: record.CIADimensionV2{Level: "ok", Checks: []record.CIACheckV2{{Healthz: &record.CombinedCheck{ID: "healthz", Level: "ok", Code: "ok"}}}}}}}
	switch latam {
	case "up":
		v2.Witnesses["latam"] = record.WitnessEntry{Status: "ok", Measured: &record.Measured{Probes: probe("ok"), Logs: map[string]record.WitnessLog{}, Peer: &record.WitnessPeer{Verdict: "ok"}}}
	case "mismatch":
		v2.Witnesses["latam"] = record.WitnessEntry{Status: "ok", Measured: &record.Measured{Probes: probe("ok"), Logs: map[string]record.WitnessLog{}, Peer: &record.WitnessPeer{Verdict: "mismatch"}}}
	case "vantage":
		v2.Witnesses["latam"] = record.WitnessEntry{Status: "ok", Measured: &record.Measured{Probes: probe("vantage"), Logs: map[string]record.WitnessLog{}}}
	case "down":
		v2.Witnesses["latam"] = record.WitnessEntry{Status: "unavailable", Reason: reason("timeout")}
	case "signature":
		v2.Witnesses["latam"] = record.WitnessEntry{Status: "unavailable", Reason: reason("signature")}
	case "off":
		v2.Witnesses["latam"] = record.WitnessEntry{Status: "unavailable", Reason: reason("off")}
	}
	for _, f := range extra {
		f(v2)
	}
	return v2.AsRun()
}

func witnessEvents(t *testing.T, states ...string) []string {
	t.Helper()
	var runs []*record.CIARun
	for i, s := range states {
		runs = append(runs, witnessRun(i, s))
	}
	var out []string
	for _, c := range Changes(ChangeInput{Runs: runs, Complete: true}) {
		if strings.HasPrefix(c.Kind, "witness-") {
			out = append(out, c.ID[len(Stamp(day)):]+"@"+c.At[11:16]+"/"+c.Since[11:16])
		}
	}
	return out
}

// A witness is unavailable after three consecutive absent runs and restored
// after two present ones; a single lost answer is not news.
func TestWitnessAvailabilityEvents(t *testing.T) {
	for _, c := range []struct {
		name   string
		states []string
		want   string // newest first, id suffix @at/since
	}{
		{"always there", []string{"up", "up", "up", "up"}, ""},
		{"one lost answer", []string{"up", "down", "up", "up"}, ""},
		{"two lost answers", []string{"up", "down", "down", "up", "up"}, ""},
		{"three: unavailable on the third, since the first", []string{"up", "down", "down", "down"}, "-witness-latam-unavailable@00:15/00:05"},
		{"a silence of five, then two good runs: restored", []string{"up", "down", "down", "down", "down", "down", "up", "up"}, "-witness-latam-restored@00:35/00:30 -witness-latam-unavailable@00:15/00:05"},
		{"one good run is not a recovery", []string{"up", "down", "down", "down", "up", "down", "down"}, "-witness-latam-unavailable@00:15/00:05"},
		{"a witness whose probes all say vantage is absent too", []string{"up", "vantage", "vantage", "vantage"}, "-witness-latam-unavailable@00:15/00:05"},
		{"not configured is not absent", []string{"off", "off", "off", "off"}, ""},
		{"not configured resets the count", []string{"up", "down", "down", "off", "down"}, ""},
		{"a cia-run/v1 record neither adds nor breaks anything", []string{"", "up", "up"}, ""},
	} {
		if got := strings.Join(witnessEvents(t, c.states...), " "); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

// A disagreement is told once, on its first run: an answer that did not verify,
// and a secondary that found the published history changed.
func TestWitnessDisagreementEvents(t *testing.T) {
	for _, c := range []struct {
		name   string
		states []string
		want   string
	}{
		{"an answer that does not verify", []string{"up", "signature", "up"}, "-witness-latam-disagreement@00:05/00:05"},
		{"told once for a run of them", []string{"up", "signature", "signature", "up"}, "-witness-latam-disagreement@00:05/00:05"},
		{"told again after it ended", []string{"signature", "up", "signature"}, "-witness-latam-disagreement@00:10/00:10 -witness-latam-disagreement@00:00/00:00"},
		{"a mismatch of the peer check", []string{"up", "mismatch"}, "-witness-latam-disagreement@00:05/00:05"},
	} {
		if got := strings.Join(witnessEvents(t, c.states...), " "); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

func TestDisagreementTextsSayWhatHappened(t *testing.T) {
	answer, peer := disagreementSummary("latam", "answer"), disagreementSummary("latam", "peer")
	if !strings.Contains(answer.EN, "could not be verified") || !strings.Contains(peer.PTBR, "registro diferente") {
		t.Errorf("%+v %+v", answer, peer)
	}
	if u := unavailableSummary("latam"); !strings.Contains(u.EN, "not an outage") || !strings.Contains(u.PTBR, "da América Latina") || !strings.Contains(u.PTBR, "não é uma queda dos serviços") {
		t.Errorf("%+v", u)
	}
	if u := unavailableSummary("asia"); !strings.Contains(u.PTBR, "de asia") {
		t.Errorf("a region without a name of its own is called by its id: %+v", u)
	}
}

// Two witnesses that read different roots for one size of a log are a split view,
// told once.
func TestSplitViewEvents(t *testing.T) {
	size, rootA, rootB := uint64(9236), "A", "B"
	split := func(roots ...string) func(*record.CIARunV2) {
		return func(v2 *record.CIARunV2) {
			for i, w := range []string{"europe", "latam"} {
				e := v2.Witnesses[w]
				if e.Measured == nil || roots[i] == "" {
					continue
				}
				root := roots[i]
				e.Measured.Logs["signs"] = record.WitnessLog{Code: "ok", Size: &size, Root: &root}
				v2.Witnesses[w] = e
			}
			svc := v2.Services["vault"]
			svc.Integrity.Checks = append(svc.Integrity.Checks, record.CIACheckV2{Log: &record.CombinedLog{ID: "log:signs", Level: "fail", Code: "finding", Finding: new(string)}})
			v2.Services["vault"] = svc
		}
	}
	runs := []*record.CIARun{
		witnessRun(0, "up", split(rootA, rootA)),
		witnessRun(1, "up", split(rootA, rootB)),
		witnessRun(2, "up", split(rootA, rootB)),
		witnessRun(3, "up", split(rootA, rootA)),
		witnessRun(4, "up", split(rootA, "")),
	}
	var got []string
	for _, c := range Changes(ChangeInput{Runs: runs, Complete: true}) {
		if c.Kind == "witness-disagreement" {
			got = append(got, c.ID+" "+c.Summary.EN)
		}
	}
	if want := "202610010005-log-signs-disagreement The witnesses saw two different trees of log signs"; len(got) != 1 || got[0] != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if logs := SplitViews(runs[3].V2); len(logs) != 0 {
		t.Errorf("the same root is no split view: %v", logs)
	}
	if logs := SplitViews(runs[1].V2); len(logs) != 1 || logs[0] != "signs" {
		t.Errorf("split views %v", logs)
	}
}

// A level change that is regional names the region that could not reach the
// service, in both languages.
func TestRegionalLevelChangeNamesTheRegion(t *testing.T) {
	regional := func(v2 *record.CIARunV2) {
		svc := v2.Services["vault"]
		svc.Availability = record.CIADimensionV2{Level: "warn", Checks: []record.CIACheckV2{{Healthz: &record.CombinedCheck{ID: "healthz", Level: "warn", Code: "regional", Error: new(string)}}}}
		v2.Services["vault"] = svc
		e := v2.Witnesses["latam"]
		e.Measured.Probes["vault"] = record.Probe{Code: "timeout", Attempts: 2}
		v2.Witnesses["latam"] = e
	}
	runs := []*record.CIARun{witnessRun(0, "up"), witnessRun(1, "up", regional), witnessRun(2, "up", regional), witnessRun(3, "up", regional)}
	var got *record.CIAChange
	for _, c := range Changes(ChangeInput{Runs: runs, Complete: true}) {
		if c.Kind == "level-changed" {
			got = &c
		}
	}
	if got == nil || got.At != "2026-10-01T00:15:00Z" || got.Since != "2026-10-01T00:05:00Z" {
		t.Fatalf("level change %+v", got)
	}
	if got.Summary.EN != "vault availability: up → degraded (unreachable from Latin America)" ||
		got.Summary.PTBR != "vault disponibilidade: no ar → degradado (inacessível a partir da América Latina)" {
		t.Errorf("summary %q / %q", got.Summary.EN, got.Summary.PTBR)
	}
}

// For a cia-run/v2 record a vantage failure is: no witness measured anything. One
// witness whose own network failed while another measured is not news about
// the record.
func TestVantageEventNeedsEveryWitnessToBeBlind(t *testing.T) {
	blind := func(v2 *record.CIARunV2) {
		svc := v2.Services["vault"]
		svc.Availability = record.CIADimensionV2{Level: "none", Checks: []record.CIACheckV2{{Healthz: &record.CombinedCheck{ID: "healthz", Level: "none", Code: "vantage"}}}}
		v2.Services["vault"] = svc
	}
	if isVantageFailure(witnessRun(0, "up")) || !isVantageFailure(witnessRun(0, "down", blind)) {
		t.Error("isVantageFailure misreads a cia-run/v2 record")
	}
}
