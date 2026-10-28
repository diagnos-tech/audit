package cia

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

var day = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func at(i int) time.Time { return day.Add(time.Duration(i) * record.SlotLength) }

func TestWorst(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{nil, "none"}, {[]string{"none", "none"}, "none"}, {[]string{"none", "ok"}, "ok"},
		{[]string{"ok", "warn", "none"}, "warn"}, {[]string{"warn", "fail", "ok"}, "fail"},
	} {
		if got := Worst(c.in...); got != c.want {
			t.Errorf("Worst(%v) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestLetters(t *testing.T) {
	for level, want := range map[string]byte{"ok": 'o', "warn": 'w', "fail": 'f', "none": '-'} {
		if Letter(level) != want {
			t.Errorf("Letter(%s) = %c", level, Letter(level))
		}
	}
}

// Every row of the table of CONTRACTS §7.2.
func TestLevelOfCode(t *testing.T) {
	for _, c := range []struct{ id, code, level string }{
		{"healthz", "ok", "ok"}, {"healthz", "retried", "ok"}, {"healthz", "slow", "warn"}, {"healthz", "tls-expiring", "warn"},
		{"healthz", "timeout", "fail"}, {"healthz", "wrong-environment", "fail"},
		{"checkpoint:audit", "ok", "ok"}, {"checkpoint:signs", "unreachable", "fail"},
		{"release", "verified", "ok"}, {"release", "pending", "warn"}, {"release", "unmonitored", "warn"},
		{"release", "served-mismatch", "fail"}, {"release", "unreachable", "none"},
		{"log:audit", "ok", "ok"}, {"log:audit", "log-error", "warn"}, {"log:signs", "halted", "fail"}, {"log:signs", "unreachable", "none"},
		{"incidents", "clear", "ok"}, {"incidents", "invalid", "warn"}, {"incidents", "incident-high", "fail"}, {"incidents", "unavailable", "none"},
	} {
		if got, ok := LevelOfCode(c.id, c.code); !ok || got != c.level {
			t.Errorf("%s %s = %q %v, want %s", c.id, c.code, got, ok, c.level)
		}
	}
	if _, ok := LevelOfCode("healthz", "verified"); ok {
		t.Error("a release code was accepted for healthz")
	}
	if _, ok := LevelOfCode("nothing", "ok"); ok {
		t.Error("an unknown check was accepted")
	}
}

// The thresholds of the day letter, one case per boundary.
func TestDayLetter(t *testing.T) {
	for _, c := range []struct {
		dim            string
		ok, warn, fail int
		want           byte
	}{
		{"availability", 0, 0, 0, '-'}, {"availability", 288, 0, 0, 'o'},
		{"availability", 287, 1, 0, 'w'}, {"availability", 287, 0, 1, 'w'}, {"availability", 286, 0, 2, 'w'},
		{"availability", 285, 0, 3, 'f'}, {"availability", 0, 0, 288, 'f'}, {"availability", 0, 5, 3, 'f'},
		{"integrity", 0, 0, 0, '-'}, {"integrity", 288, 0, 0, 'o'}, {"integrity", 287, 1, 0, 'w'},
		{"integrity", 287, 0, 1, 'f'}, {"integrity", 100, 100, 1, 'f'},
		{"confidentiality", 0, 0, 0, '-'}, {"confidentiality", 10, 0, 0, 'o'}, {"confidentiality", 9, 1, 0, 'w'},
		{"confidentiality", 9, 0, 1, 'f'},
	} {
		if got := DayLetter(c.dim, c.ok, c.warn, c.fail); got != c.want {
			t.Errorf("DayLetter(%s, %d, %d, %d) = %c, want %c", c.dim, c.ok, c.warn, c.fail, got, c.want)
		}
	}
}

func dims(avail, integ, conf Result) Dims { return Dims{avail, integ, conf} }

var okDims = dims(Result{"ok", "ok"}, Result{"ok", "verified"}, Result{"ok", "clear"})

func slotWith(i int, services map[string]Dims) *Slot { return &Slot{Time: at(i), Services: services} }

func TestBuildDayLettersRunsAndSpans(t *testing.T) {
	slow := dims(Result{"warn", "slow"}, okDims[1], okDims[2])
	down := dims(Result{"fail", "timeout"}, Result{"none", "unreachable"}, okDims[2])
	in := DayInput{Day: day}
	for i, d := range []Dims{okDims, okDims, slow, slow, okDims, down, down, okDims, slow, okDims} {
		in.Slots[i] = slotWith(i, map[string]Dims{"vault": d})
	}
	in.Slots[9] = nil // the auditor did not run in slot 9
	got := BuildDay(in)
	if got.Runs[:10] != "1111111110" || strings.Contains(got.Runs[10:], "1") {
		t.Errorf("runs %q", got.Runs[:12])
	}
	l := got.Services["vault"]
	if l.Availability[:10] != "oowwoffow-" || l.Integrity[:10] != "ooooo--oo-" || l.Confidentiality[:10] != "ooooooooo-" {
		t.Errorf("letters %q %q %q", l.Availability[:10], l.Integrity[:10], l.Confidentiality[:10])
	}
	if l.Availability[10:] != strings.Repeat("-", 278) {
		t.Error("slots without a run must be -")
	}
	want := []string{
		"vault|availability|2|3|warn|slow|",
		"vault|availability|5|6|fail|timeout|",
		"vault|availability|8|8|warn|slow|",
		"vault|integrity|5|6|none|unreachable|",
	}
	if len(got.Spans) != len(want) {
		t.Fatalf("spans %+v", got.Spans)
	}
	for i := range want {
		if sprint(got.Spans[i]) != want[i] {
			t.Errorf("span %d = %s, want %s", i, sprint(got.Spans[i]), want[i])
		}
	}
}

func sprint(s record.CIASpan) string {
	return fmt.Sprintf("%s|%s|%d|%d|%s|%s|%s", s.Service, s.Dimension, s.From, s.To, s.Level, s.Code, strings.Join(s.Incidents, "+"))
}

func TestSpansSplitWhenTheCodeChanges(t *testing.T) {
	in := DayInput{Day: day}
	codes := []string{"slow", "slow", "tls-expiring", "tls-expiring", "slow"}
	for i, c := range codes {
		in.Slots[i] = slotWith(i, map[string]Dims{"sign": dims(Result{"warn", c}, okDims[1], okDims[2])})
	}
	if n := len(BuildDay(in).Spans); n != 3 {
		t.Errorf("%d spans, want 3 (slow, tls-expiring, slow)", n)
	}
}

// A day's confidentiality is recomputed from the newest snapshot, so an
// incident colours the slots before it was declared, from its start.
func TestConfidentialityIsRecolouredFromTheLatestSnapshot(t *testing.T) {
	resolved := at(10).Add(2 * time.Minute) // resolved in the middle of slot 10
	incs := Incidents{
		{ID: "2026-10-01-low", Services: []string{"sign"}, Categories: []string{"C"}, Level: "warn", Start: at(4).Add(time.Minute), End: &resolved},
		{ID: "2026-10-01-high", Services: []string{"sign", "vault"}, Categories: []string{"C"}, Level: "fail", Start: at(7)},
	}
	in := DayInput{Day: day, Colour: Colourer{Incidents: incs, HaveSnapshot: true}}
	for i := 0; i < 14; i++ {
		in.Slots[i] = slotWith(i, map[string]Dims{"sign": okDims, "vault": okDims, "audit": okDims})
	}
	got := BuildDay(in)
	for service, want := range map[string]string{
		"sign":  "oooowwwfffffff", // low from slot 4 to 10, high from slot 7
		"vault": "ooooooofffffff",
		"audit": "oooooooooooooo",
	} {
		if c := got.Services[service].Confidentiality[:14]; c != want {
			t.Errorf("%s confidentiality %q, want %q", service, c, want)
		}
	}
	var spans []string
	for _, s := range got.Spans {
		if s.Service == "sign" {
			spans = append(spans, sprint(s))
		}
	}
	want := []string{
		"sign|confidentiality|4|6|warn|incident-low|2026-10-01-low",
		"sign|confidentiality|7|10|fail|incident-high|2026-10-01-high+2026-10-01-low",
		"sign|confidentiality|11|13|fail|incident-high|2026-10-01-high",
	}
	if strings.Join(spans, "\n") != strings.Join(want, "\n") {
		t.Errorf("sign spans:\n%s\nwant:\n%s", strings.Join(spans, "\n"), strings.Join(want, "\n"))
	}
}

func TestWithoutASnapshotTheRunsOwnLevelStands(t *testing.T) {
	in := DayInput{Day: day}
	in.Slots[0] = slotWith(0, map[string]Dims{"sign": dims(okDims[0], okDims[1], Result{"warn", "incident-low"})})
	if c := BuildDay(in).Services["sign"].Confidentiality[0]; c != 'w' {
		t.Errorf("letter %c, want w", c)
	}
}

func TestInvalidIncidentFileKeepsTheWorseLevel(t *testing.T) {
	in := DayInput{Day: day, Colour: Colourer{HaveSnapshot: true}}
	in.Slots[0] = slotWith(0, map[string]Dims{"sign": dims(okDims[0], okDims[1], Result{"warn", "invalid"})})
	got := BuildDay(in)
	if c := got.Services["sign"].Confidentiality[0]; c != 'w' || got.Spans[0].Code != "invalid" {
		t.Errorf("letter %c, spans %+v", c, got.Spans)
	}
}

func TestAffectingBoundaries(t *testing.T) {
	end := at(10)
	inc := Incidents{{ID: "x", Services: []string{"vault"}, Categories: []string{"A"}, Level: "warn", Start: at(5).Add(4 * time.Minute), End: &end}}
	for i, want := range map[int]bool{4: false, 5: true, 9: true, 10: false} { // a slot is [t, t+5m)
		if got := len(inc.Affecting("vault", "availability", at(i))) == 1; got != want {
			t.Errorf("slot %d affected = %v, want %v", i, got, want)
		}
	}
	if len(inc.Affecting("sign", "availability", at(6))) != 0 {
		t.Error("an incident affected a service it does not list")
	}
	if len(inc.Affecting("vault", "integrity", at(6))) != 0 || len(inc.Affecting("vault", "confidentiality", at(6))) != 0 {
		t.Error("an availability incident coloured another dimension")
	}
}

func TestBuildSummaryWindowAndUptime(t *testing.T) {
	days := map[string]*record.CIADay{}
	for k := 0; k < 3; k++ {
		d := day.AddDate(0, 0, -k)
		in := DayInput{Day: d, Colour: Colourer{HaveSnapshot: true}}
		for i := 0; i < 288; i++ {
			dm := okDims
			if k == 0 && i < 3 {
				dm = dims(Result{"fail", "timeout"}, Result{"none", "unreachable"}, okDims[2])
			}
			if k == 1 && i == 0 {
				dm = dims(Result{"warn", "slow"}, okDims[1], okDims[2])
			}
			in.Slots[i] = &Slot{Time: d.Add(time.Duration(i) * record.SlotLength), Services: map[string]Dims{"vault": dm}}
		}
		days[d.Format(record.DayLayout)] = BuildDay(in)
	}
	first := day.AddDate(0, 0, -2)
	s := BuildSummary(days, first, day, "2026-10-01T00:10:00Z")
	if s.To != "2026-10-01" || s.From != "2026-07-04" || s.FirstRun != "2026-09-29T00:00:00Z" {
		t.Errorf("window %s..%s firstRun %s", s.From, s.To, s.FirstRun)
	}
	v := s.Services["vault"]
	if v.Availability.Days[87:] != "owf" || len(v.Availability.Days) != 90 || v.Availability.Days[:87] != strings.Repeat("-", 87) {
		t.Errorf("availability days %q", v.Availability.Days)
	}
	if v.Integrity.Days[87:] != "ooo" {
		t.Errorf("integrity days %q", v.Integrity.Days[87:])
	}
	if c := v.Availability.Counts[89]; c != [4]int{285, 0, 3, 0} {
		t.Errorf("counts of the last day %v", c)
	}
	if c := v.Integrity.Counts[89]; c != [4]int{285, 0, 0, 3} {
		t.Errorf("none slots with a run are counted in the fourth column: %v", c)
	}
	if v.Uptime.Up != 288*3-3 || v.Uptime.Measured != 288*3 {
		t.Errorf("uptime %+v", v.Uptime)
	}
	if len(v.Availability.Counts) != 90 {
		t.Errorf("%d counts", len(v.Availability.Counts))
	}
}

func TestSince(t *testing.T) {
	mk := func(levels ...string) []Slot {
		var chain []Slot
		for i, l := range levels {
			svc := map[string]Dims{"vault": dims(Result{l, "x"}, okDims[1], okDims[2])}
			if l == "gone" {
				svc = map[string]Dims{}
			}
			chain = append(chain, Slot{Time: at(i * 3), Services: svc}) // time gaps do not matter
		}
		return chain
	}
	for _, c := range []struct {
		name    string
		chain   []Slot
		want    time.Time
		reached bool
	}{
		{"one run", mk("ok"), at(0), true},
		{"changed once", mk("ok", "warn", "warn", "warn"), at(3), false},
		{"always the same", mk("ok", "ok", "ok"), at(0), true},
		{"recovered", mk("warn", "warn", "ok", "ok"), at(6), false},
		{"flapping", mk("ok", "warn", "ok"), at(6), false},
		{"service missing from a run", mk("ok", "gone", "ok", "ok"), at(6), false},
	} {
		got, reached := Since(c.chain, Colourer{}, "vault", "availability")
		if !got.Equal(c.want) || reached != c.reached {
			t.Errorf("%s: %v %v, want %v %v", c.name, got, reached, c.want, c.reached)
		}
	}
}

func TestFirstCodeAndBuildLatest(t *testing.T) {
	version := "1.2.3"
	run := &record.CIARun{Schema: "cia-run/v1", Slot: "2026-10-01T14:20:00Z", FinishedAt: "2026-10-01T14:20:07Z",
		Services: map[string]record.CIAService{"vault": {
			URL: "https://vault.example/",
			Availability: record.CIADimension{Level: "warn", Checks: []record.CIACheck{
				{Healthz: &record.HealthzCheck{ID: "healthz", Level: "ok", Code: "ok", LatencyMs: intp(80)}},
				{Checkpoint: &record.CheckpointCheck{ID: "checkpoint:a", Level: "warn", Code: "x"}},
			}},
			Integrity: record.CIADimension{Level: "ok", Checks: []record.CIACheck{
				{Release: &record.ReleaseCheck{ID: "release", Level: "ok", Code: "verified", Version: &version}},
			}},
			Confidentiality: record.CIADimension{Level: "ok", Checks: []record.CIACheck{
				{Incidents: &record.IncidentsCheck{ID: "incidents", Level: "ok", Code: "clear", Open: []string{}}},
			}},
		}}}
	if got := FirstCode(run.Services["vault"].Availability); got != "x" {
		t.Errorf("FirstCode = %s: the first check with the dimension's level", got)
	}
	latest := BuildLatest(LatestInput{Run: run, Path: "data/v1/cia/runs/2026/10/01/1420Z.json", FirstRun: day,
		Since: func(string, string) time.Time { return at(1) }})
	v := latest.Services["vault"]
	if latest.Headline.Availability != "warn" || v.Availability.Code != "x" || v.Availability.LatencyMs == nil ||
		*v.Availability.LatencyMs != 80 || v.Integrity.Version == nil || v.Availability.Since != "2026-10-01T00:05:00Z" {
		t.Errorf("%+v", latest)
	}
	if latest.UpdatedAt != "2026-10-01T14:20:07Z" || len(latest.Incidents.Open) != 0 || latest.Incidents.Snapshot != nil {
		t.Errorf("%+v", latest.Incidents)
	}
}

func intp(i int) *int { return &i }
