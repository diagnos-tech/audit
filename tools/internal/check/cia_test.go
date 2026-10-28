package check

import (
	"fmt"
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

func healthz(level, code string) record.CIACheck {
	status, latency := 200, 90
	return record.CIACheck{Healthz: &record.HealthzCheck{ID: "healthz", Level: level, Code: code, Attempts: 1, HTTPStatus: &status, LatencyMs: &latency}}
}

func checkpoint(name, level, code string) record.CIACheck {
	return record.CIACheck{Checkpoint: &record.CheckpointCheck{ID: "checkpoint:" + name, Level: level, Code: code}}
}

func TestDimensionProblems(t *testing.T) {
	for _, c := range []struct {
		name string
		dim  string
		d    record.CIADimension
		want string // "" = accepted
	}{
		{"healthz ok", "availability", record.CIADimension{Level: "ok", Checks: []record.CIACheck{healthz("ok", "ok")}}, ""},
		{"worst of two", "availability", record.CIADimension{Level: "fail", Checks: []record.CIACheck{healthz("ok", "ok"), checkpoint("audit", "fail", "unreachable")}}, ""},
		{"level not the worst", "availability", record.CIADimension{Level: "ok", Checks: []record.CIACheck{healthz("warn", "slow")}}, "not the worst"},
		{"level of the code", "availability", record.CIADimension{Level: "ok", Checks: []record.CIACheck{healthz("ok", "slow")}}, "must be warn"},
		{"code of another family", "availability", record.CIADimension{Level: "ok", Checks: []record.CIACheck{healthz("ok", "verified")}}, "not a code of healthz"},
		{"wrong dimension", "integrity", record.CIADimension{Level: "ok", Checks: []record.CIACheck{healthz("ok", "ok")}}, "does not belong"},
		{"checkpoint first", "availability", record.CIADimension{Level: "ok", Checks: []record.CIACheck{checkpoint("a", "ok", "ok"), healthz("ok", "ok")}}, "first check must be healthz"},
		{"checkpoints unsorted", "availability", record.CIADimension{Level: "ok", Checks: []record.CIACheck{healthz("ok", "ok"), checkpoint("signs", "ok", "ok"), checkpoint("audit", "ok", "ok")}}, "sorted"},
		{"checkpoints repeated", "availability", record.CIADimension{Level: "ok", Checks: []record.CIACheck{healthz("ok", "ok"), checkpoint("a", "ok", "ok"), checkpoint("a", "ok", "ok")}}, "sorted"},
		{"retried needs two attempts", "availability", record.CIADimension{Level: "ok", Checks: []record.CIACheck{healthz("ok", "retried")}}, "attempts"},
		{"empty", "integrity", record.CIADimension{Level: "none"}, "first check must be release"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(dimensionProblems(c.dim, c.d), "; ")
			if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
				t.Errorf("problems %q, want one mentioning %q", got, c.want)
			}
		})
	}
}

func TestReleaseFieldProblems(t *testing.T) {
	s := func(v string) *string { return &v }
	for name, c := range map[string]struct {
		x    record.ReleaseCheck
		want string
	}{
		"unreachable with a digest":  {record.ReleaseCheck{Code: "unreachable", Digest: s("d")}, "no release"},
		"unsigned with a digest":     {record.ReleaseCheck{Code: "unsigned", Digest: s("d")}, "no digest"},
		"pending with a verdict":     {record.ReleaseCheck{Code: "pending", Digest: s("d"), Verdict: s("v"), FirstSeen: s("t")}, "pending"},
		"verified without a verdict": {record.ReleaseCheck{Code: "verified", Digest: s("d"), Version: s("1"), Commit: s("c")}, "needs"},
		"verdict outside the digest": {record.ReleaseCheck{Code: "verified", Digest: s("d"), Version: s("1"), Commit: s("c"), Verdict: s("data/x/verdict.json")}, "under the digest"},
		"mismatch without a sample":  {record.ReleaseCheck{Code: "served-mismatch", Digest: s("d"), Version: s("1"), Commit: s("c"), Verdict: s("data/d/verdict.json")}, "sampled mismatch"},
		"more checked than served": {record.ReleaseCheck{Code: "verified", Digest: s("d"), Version: s("1"), Commit: s("c"), Verdict: s("data/d/verdict.json"),
			Served: &record.ServedSample{Checked: 3, Total: 2}}, "more files"},
	} {
		if got := strings.Join(releaseFieldProblems(&c.x), ";"); !strings.Contains(got, c.want) {
			t.Errorf("%s: %q does not mention %q", name, got, c.want)
		}
	}
}

func TestLogFieldProblems(t *testing.T) {
	if p := logFieldProblems(&record.LogCheck{ID: "log:a", Status: "witnessed", Code: "halted"}); len(p) != 1 {
		t.Error("a witnessed log with code halted was accepted")
	}
	if p := logFieldProblems(&record.LogCheck{ID: "log:a", Status: "halted", Code: "halted"}); len(p) != 1 {
		t.Error("a halted log without its finding was accepted")
	}
	finding := "data/v1/a/findings/2026/10/01/133507Z.json"
	if p := logFieldProblems(&record.LogCheck{ID: "log:a", Status: "halted", Code: "halted", Finding: &finding}); len(p) != 0 {
		t.Errorf("%v", p)
	}
}

func TestSnapshotFor(t *testing.T) {
	snaps := []string{"data/v1/cia/incidents/2026/09/30/1815Z.json", "data/v1/cia/incidents/2026/10/01/0935Z.json"}
	for slot, want := range map[string]string{
		"2026-09-30T18:10:00Z": "",
		"2026-09-30T18:15:00Z": snaps[0],
		"2026-10-01T09:30:00Z": snaps[0],
		"2026-10-01T09:35:00Z": snaps[1],
		"2026-10-02T00:00:00Z": snaps[1],
	} {
		if got := snapshotFor(snaps, slot); got != want {
			t.Errorf("snapshotFor(%s) = %q, want %q", slot, got, want)
		}
	}
}

func TestClipSpansCutsAtSlotsWithoutRecords(t *testing.T) {
	var present [cia.SlotsPerDay]bool
	for i := 10; i < 20; i++ {
		present[i] = true
	}
	present[15] = false
	clipped := clipSpans([]record.CIASpan{{From: 5, To: 12}, {From: 14, To: 18}, {From: 30, To: 31}}, present)
	var got []string
	for _, s := range clipped {
		got = append(got, fmt.Sprintf("%d-%d", s.From, s.To))
	}
	if strings.Join(got, ",") != "10-12,14-14,16-18" {
		t.Errorf("clipped %v", got)
	}
}

func TestValidateDay(t *testing.T) {
	zero := make([]*int, cia.SlotsPerDay)
	letters := func(s string) string { return s + strings.Repeat("-", cia.SlotsPerDay-len(s)) }
	runs := "1111" + strings.Repeat("0", cia.SlotsPerDay-4)
	day := func(avail string, spans ...record.CIASpan) *record.CIADay {
		return &record.CIADay{Runs: runs, Spans: spans, Services: map[string]record.CIADayLetters{
			"vault": {Availability: letters(avail), Integrity: letters("oooo"), Confidentiality: letters("oooo"),
				Latency: cia.DayLatency(zero)},
		}}
	}
	span := func(from, to int, level string) record.CIASpan {
		return record.CIASpan{Service: "vault", Dimension: "availability", From: from, To: to, Level: level, Code: "slow", Incidents: []string{}}
	}
	for name, c := range map[string]struct {
		d    *record.CIADay
		want string
	}{
		"consistent":                   {day("owwo", span(1, 2, "warn")), ""},
		"letter where no run":          {day("oooow"), "no run was recorded"},
		"letter without a span":        {day("owwo"), "no span covers"},
		"span over a different letter": {day("owwo", span(1, 3, "warn")), "is not a warn slot"},
		"span past the day":            {day("owwo", span(1, 300, "warn")), "covers slots"},
		"span of an unknown service":   {&record.CIADay{Runs: runs, Services: map[string]record.CIADayLetters{}, Spans: []record.CIASpan{span(1, 2, "warn")}}, "does not have"},
		"spans overlap":                {day("owwo", span(1, 2, "warn"), span(2, 3, "warn")), "overlaps"},
		"spans out of order":           {day("owwo", span(2, 2, "warn"), span(1, 1, "warn")), "out of order"},
	} {
		got := strings.Join(validateDay(c.d), ";")
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func TestCompareDaySkipsSlotsWithoutRecords(t *testing.T) {
	var present [cia.SlotsPerDay]bool
	present[0], present[1] = true, true
	full := func(a string) *record.CIADay {
		return &record.CIADay{Runs: "11" + strings.Repeat("1", cia.SlotsPerDay-2), Services: map[string]record.CIADayLetters{
			"vault": {Availability: a + strings.Repeat("o", cia.SlotsPerDay-len(a)), Integrity: strings.Repeat("o", 288), Confidentiality: strings.Repeat("o", 288)},
		}}
	}
	want, got := full("oo"), full("ow")
	if d := compareDay(want, got, present, false); len(d) == 0 {
		t.Error("a differing slot that has a record was not noticed")
	}
	got = full("oo")
	got.Services["vault"] = record.CIADayLetters{Availability: "oo" + strings.Repeat("w", 286), Integrity: strings.Repeat("o", 288), Confidentiality: strings.Repeat("o", 288)}
	if d := compareDay(want, got, present, false); len(d) != 0 {
		t.Errorf("slots without a record were compared: %v", d)
	}
	if d := compareDay(want, got, present, true); len(d) == 0 {
		t.Error("-complete must compare every slot")
	}
}

func TestLatencyProblem(t *testing.T) {
	runs := strings.Repeat("1", 4) + strings.Repeat("0", 284)
	slotsOf := func(v ...int) []*int {
		out := make([]*int, cia.SlotsPerDay)
		for i := range v {
			if v[i] >= 0 {
				out[i] = &v[i]
			}
		}
		return out
	}
	consistent := cia.DayLatency(slotsOf(100, 300, 200, -1))
	wrongP95 := cia.DayLatency(slotsOf(100, 300, 200, -1))
	*wrongP95.P95Ms = 250
	wrongSamples := cia.DayLatency(slotsOf(100, 300, 200, -1))
	wrongSamples.Samples = 4
	outsideRun := cia.DayLatency(slotsOf(100, 300, 200, 100, 50))
	short := cia.DayLatency(slotsOf(100))
	short.SlotsMs = short.SlotsMs[:100]
	noSlots := cia.DayLatency(slotsOf(100))
	noSlots.SlotsMs = nil
	for name, c := range map[string]struct {
		l    *record.CIALatency
		want string
	}{
		"consistent":                 {consistent, ""},
		"no samples":                 {cia.DayLatency(slotsOf()), ""},
		"missing":                    {nil, "has no latency"},
		"without slotsMs":            {noSlots, "slotsMs has 0 entries"},
		"too few slotsMs":            {short, "slotsMs has 100 entries"},
		"a latency without a run":    {outsideRun, "slot 4, where no run was recorded"},
		"p95 that does not follow":   {wrongP95, "does not follow from its slotsMs"},
		"samples that do not follow": {wrongSamples, "does not follow from its slotsMs"},
	} {
		got := latencyProblem(c.l, runs)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func TestTimingsProblems(t *testing.T) {
	ms := func(v int) *int { return &v }
	check := func(latency *int, t0 *record.Timings) string {
		return strings.Join(timingsProblems(&record.HealthzCheck{LatencyMs: latency, Timings: t0}), ";")
	}
	ok := &record.Timings{DNSMs: ms(5), ConnectMs: ms(10), TLSMs: ms(20), FirstByteMs: ms(60), TotalMs: 100}
	if p := check(ms(100), ok); p != "" {
		t.Errorf("consistent timings rejected: %s", p)
	}
	if p := check(nil, nil); p != "" {
		t.Errorf("no timings: %s", p)
	}
	if p := check(ms(101), ok); !strings.Contains(p, "is not latencyMs 101") {
		t.Errorf("total differing from the latency: %q", p)
	}
	if p := check(nil, &record.Timings{ConnectMs: ms(30), TotalMs: 8000}); p != "" {
		t.Errorf("a timeout has a total but no latency: %q", p)
	}
	for name, phase := range map[string]*record.Timings{
		"dnsMs": {DNSMs: ms(101), TotalMs: 100}, "connectMs": {ConnectMs: ms(101), TotalMs: 100},
		"tlsMs": {TLSMs: ms(101), TotalMs: 100}, "firstByteMs": {FirstByteMs: ms(101), TotalMs: 100},
	} {
		if p := check(ms(100), phase); !strings.Contains(p, name+" 101 is longer") {
			t.Errorf("%s longer than the attempt: %q", name, p)
		}
	}
	if p := check(ms(100), &record.Timings{FirstByteMs: ms(100), TotalMs: 100}); p != "" {
		t.Errorf("a phase as long as the attempt is allowed: %q", p)
	}
}

func TestVantagePattern(t *testing.T) {
	for v, ok := range map[string]bool{"scaleway:fr-par": true, "aws:eu-west-1": true, "scaleway": false, "Scaleway:fr-par": false,
		"scaleway:": false, ":fr-par": false, "scaleway:fr par": false} {
		if vantageRE.MatchString(v) != ok {
			t.Errorf("vantage %q accepted = %v", v, !ok)
		}
	}
}
