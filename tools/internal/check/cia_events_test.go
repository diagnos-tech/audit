package check

import (
	"strings"
	"testing"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

var t0 = time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC)

func slotN(n int) time.Time { return t0.Add(time.Duration(n) * record.SlotLength) }

func ev(typ string, seq, at int) record.CIAIncidentEvent {
	e := record.CIAIncidentEvent{Schema: "cia-incident-event/v1", ID: "2026-10-01-auto-vault-a-0300", Seq: seq, Type: typ,
		At: record.FormatTime(slotN(at)), Source: "auditor", Categories: []string{"A"}, Services: []string{"vault"}, Severity: "high",
		StartedAt: record.FormatTime(slotN(0)), Reasons: []string{"timeout"}, Run: record.CIARunPath(slotN(at))}
	if typ == "resolved" {
		e.ResolvedAt = ptr(record.FormatTime(slotN(at - 1)))
	}
	return e
}

func ptr[T any](v T) *T { return &v }

func TestEventSequenceRules(t *testing.T) {
	for _, c := range []struct {
		name   string
		events []record.CIAIncidentEvent
		check  int // index of the event to check
		want   string
	}{
		{"opened, updated, resolved", []record.CIAIncidentEvent{ev("opened", 1, 2), ev("updated", 2, 3), ev("resolved", 3, 5)}, 2, ""},
		{"a gap in seq", []record.CIAIncidentEvent{ev("opened", 1, 2), ev("updated", 3, 3)}, 1, "without gaps"},
		{"the first event must open", []record.CIAIncidentEvent{ev("updated", 1, 2)}, 0, "only the first opens"},
		{"only the first event opens", []record.CIAIncidentEvent{ev("opened", 1, 2), ev("opened", 2, 3)}, 1, "only the first opens"},
		{"resolved must be last", []record.CIAIncidentEvent{ev("opened", 1, 2), ev("resolved", 2, 4), ev("updated", 3, 5)}, 1, "has event 3 after it"},
		{"at must grow", []record.CIAIncidentEvent{ev("opened", 1, 4), ev("updated", 2, 4)}, 1, "not after event 1"},
		{"the services never change", []record.CIAIncidentEvent{ev("opened", 1, 2), func() record.CIAIncidentEvent {
			e := ev("updated", 2, 3)
			e.Services = []string{"sign"}
			return e
		}()}, 1, "must not change"},
		{"startedAt never changes", []record.CIAIncidentEvent{ev("opened", 1, 2), func() record.CIAIncidentEvent {
			e := ev("updated", 2, 3)
			e.StartedAt = record.FormatTime(slotN(1))
			return e
		}()}, 1, "must not change"},
	} {
		r := &Report{}
		checkEventSequence(&c.events[c.check], c.events, r)
		got := resultsText(r)
		if (c.want == "") != (r.Worst() == OK) || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func resultsText(r *Report) string {
	var b strings.Builder
	r.Print(&b, false)
	return b.String()
}

func TestEventIDAndTimes(t *testing.T) {
	e := ev("opened", 1, 2)
	if p := idProblem(&e, slotN(0)); p != "" {
		t.Errorf("a consistent id: %s", p)
	}
	for name, change := range map[string]func(*record.CIAIncidentEvent){
		"service":  func(e *record.CIAIncidentEvent) { e.Services = []string{"sign"} },
		"category": func(e *record.CIAIncidentEvent) { e.Categories = []string{"I"} },
		"start":    func(e *record.CIAIncidentEvent) { e.StartedAt = record.FormatTime(slotN(1)) },
	} {
		e := ev("opened", 1, 2)
		change(&e)
		started, _ := record.ParseTime(e.StartedAt)
		if idProblem(&e, started) == "" {
			t.Errorf("an id that disagrees with its %s was accepted", name)
		}
	}
	if p := timeProblem(&e, slotN(2), slotN(0)); p != "" {
		t.Errorf("%s", p)
	}
	resolved := ev("resolved", 2, 5)
	for name, c := range map[string]struct {
		e    record.CIAIncidentEvent
		want string
	}{
		"started after at": {func() record.CIAIncidentEvent {
			e := ev("opened", 1, 0)
			e.StartedAt = record.FormatTime(slotN(1))
			return e
		}(), "after at"},
		"resolvedAt on an open one": {func() record.CIAIncidentEvent {
			e := ev("opened", 1, 2)
			e.ResolvedAt = ptr(record.FormatTime(slotN(1)))
			return e
		}(), "only set by the resolved"},
		"resolved without a time": {func() record.CIAIncidentEvent { e := resolved; e.ResolvedAt = nil; return e }(), "has no resolvedAt"},
		"resolvedAt before start": {func() record.CIAIncidentEvent {
			e := resolved
			e.ResolvedAt = ptr(record.FormatTime(slotN(0).Add(-record.SlotLength)))
			return e
		}(), "between startedAt and at"},
		"resolvedAt after at": {func() record.CIAIncidentEvent {
			e := resolved
			e.ResolvedAt = ptr(record.FormatTime(slotN(6)))
			return e
		}(), "between startedAt and at"},
	} {
		at, _ := record.ParseTime(c.e.At)
		started, _ := record.ParseTime(c.e.StartedAt)
		if p := timeProblem(&c.e, at, started); !strings.Contains(p, c.want) {
			t.Errorf("%s: %q", name, p)
		}
	}
}

func TestOpenProblem(t *testing.T) {
	levels := func(l ...string) func(time.Time) (string, bool) {
		return func(t time.Time) (string, bool) {
			i := int(t.Sub(t0) / record.SlotLength)
			if i < 0 || i >= len(l) || l[i] == "missing" {
				return "", false
			}
			return l[i], true
		}
	}
	for _, c := range []struct {
		name     string
		category string
		m        func(time.Time) (string, bool)
		at       int
		want     string
	}{
		{"three failed slots", "A", levels("fail", "fail", "fail"), 2, ""},
		{"a neutral slot in between", "A", levels("fail", "none", "fail", "fail"), 3, ""},
		{"a good slot in between", "A", levels("fail", "ok", "fail", "fail"), 3, "availability is ok"},
		{"the first slot did not fail", "A", levels("ok", "fail", "fail"), 2, "not fail"},
		{"opened too soon", "A", levels("fail", "fail"), 1, "at least 10 minutes"},
		{"a record is not here", "A", levels("missing", "fail", "fail"), 2, ""},
		{"integrity opens at once", "I", levels("fail"), 0, ""},
		{"integrity that did not fail", "I", levels("ok"), 0, "not fail"},
	} {
		got := openProblem(c.m, c.category, slotN(0), slotN(c.at))
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func vantageRunOf(controlOK bool, healthz string, hasControl bool) *record.CIARun {
	level := "fail"
	if healthz == "vantage" {
		level = "none"
	}
	r := &record.CIARun{Services: map[string]record.CIAService{
		"vault": {Availability: record.CIADimension{Level: level, Checks: []record.CIACheck{
			{Healthz: &record.HealthzCheck{ID: "healthz", Level: level, Code: healthz}}}}},
	}}
	if hasControl {
		r.Control = &record.CIAControl{Host: "connectivity.example", OK: controlOK}
	}
	return r
}

func TestCheckVantage(t *testing.T) {
	for _, c := range []struct {
		name string
		run  *record.CIARun
		want string // "" = no complaint; "ok" = passes with a note
	}{
		{"an ordinary run", vantageRunOf(true, "ok", true), ""},
		{"one service down while the control probe works", vantageRunOf(true, "timeout", true), ""},
		{"every service down while the control probe failed", vantageRunOf(false, "timeout", true), "recorded as an outage"},
		{"no control probe, no complaint", vantageRunOf(false, "timeout", false), ""},
		{"a vantage failure", vantageRunOf(false, "vantage", true), "ok"},
		{"vantage code with a working control probe", vantageRunOf(true, "vantage", true), "did not fail"},
		{"vantage code without a control probe", vantageRunOf(false, "vantage", false), "did not fail"},
		{"a host that is not a host", func() *record.CIARun { r := vantageRunOf(true, "ok", true); r.Control.Host = "Not A Host"; return r }(), "not a host name"},
	} {
		r := &Report{}
		checkVantage(c.run, r)
		got := resultsText(r)
		switch c.want {
		case "":
			if len(r.Results) != 0 {
				t.Errorf("%s: %s", c.name, got)
			}
		case "ok":
			if r.Worst() != OK || len(r.Results) != 1 {
				t.Errorf("%s: %s", c.name, got)
			}
		default:
			if r.Worst() != Fail || !strings.Contains(got, c.want) {
				t.Errorf("%s: %s, want %q", c.name, got, c.want)
			}
		}
	}
}

func TestCoverageOfFailures(t *testing.T) {
	mk := func(avail ...string) *ciaFacts {
		f := &ciaFacts{}
		for i, l := range avail {
			f.chain = append(f.chain, cia.Slot{Time: slotN(i), Services: map[string]cia.Dims{"vault": {{Level: l}, {Level: "ok"}, {Level: "ok"}}}})
		}
		return f
	}
	incident := func(started, resolved int) *eventSet {
		o, r := ev("opened", 1, 2), ev("resolved", 2, 8)
		o.StartedAt, r.StartedAt = record.FormatTime(slotN(started)), record.FormatTime(slotN(started))
		r.ResolvedAt = ptr(record.FormatTime(slotN(resolved)))
		return &eventSet{byID: map[string][]record.CIAIncidentEvent{o.ID: {o, r}}}
	}
	none := &eventSet{byID: map[string][]record.CIAIncidentEvent{}}
	for _, c := range []struct {
		name     string
		f        *ciaFacts
		set      *eventSet
		complete bool
		want     string
	}{
		{"two failed slots need no incident", mk("ok", "fail", "fail", "ok"), none, true, ""},
		{"three failed slots need one", mk("ok", "fail", "fail", "fail", "ok"), none, true, "failed from 2026-10-01T03:05:00Z for 3"},
		{"covered by an incident", mk("ok", "fail", "fail", "fail", "ok"), incident(1, 4), true, ""},
		{"an incident that ends before the failure does", mk("ok", "fail", "fail", "fail", "ok"), incident(1, 3), true, "no availability incident"},
		{"an incident that starts after the failure does", mk("ok", "fail", "fail", "fail", "ok"), incident(2, 4), true, "no availability incident"},
		{"slots that measured nothing do not interrupt", mk("ok", "fail", "none", "fail", "fail", "ok"), incident(1, 5), true, ""},
		{"nor count", mk("ok", "fail", "none", "fail", "ok"), none, true, ""},
		{"a good slot interrupts", mk("ok", "fail", "fail", "ok", "fail", "fail", "ok"), none, true, ""},
		{"a failure at the start of a slice may have started before it", mk("fail", "fail", "fail", "ok"), none, false, ""},
		{"but not in the whole history", mk("fail", "fail", "fail", "ok"), none, true, "no availability incident"},
	} {
		got := coverageReport(c.f, c.set, c.complete)
		text := resultsText(got)
		if (c.want == "") != (got.Worst() == OK) || !strings.Contains(text, c.want) {
			t.Errorf("%s: %s, want %q", c.name, text, c.want)
		}
	}
}
