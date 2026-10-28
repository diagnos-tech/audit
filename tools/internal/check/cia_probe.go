package check

import (
	"fmt"
	"slices"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// probeProblems checks a probe against its own code: what an answer, a failure
// and a probe that measured nothing each have and lack.
func probeProblems(p record.Probe) []string {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	level, known := cia.LevelOfCodeV2("healthz", p.Code)
	switch {
	case !known || p.Code == "regional":
		return []string{fmt.Sprintf("%q is not a code of a probe", p.Code)}
	case level == record.LevelFail && (p.Class == nil || !slices.Contains(record.ErrorClasses[:], *p.Class)):
		add("a failed probe names the phase it failed in (%v)", record.ErrorClasses)
	case level != record.LevelFail && p.Class != nil:
		add("only a failed probe has an error class")
	}
	switch {
	case p.Attempts < 1 || p.Attempts > 2:
		add("attempts must be 1 or 2")
	case (p.Attempts == 2) != (p.RetriedAfter != nil) && level != record.LevelNone:
		add("retriedAfter names the class of the first attempt exactly when there were two")
	case p.RetriedAfter != nil && !slices.Contains(record.ErrorClasses[:], *p.RetriedAfter):
		add("retriedAfter %q is not an error class", *p.RetriedAfter)
	case p.Code == "retried" && p.Attempts != 2:
		add("code retried with %d attempts", p.Attempts)
	}
	if record.Succeeded(p.Code) {
		if p.HTTPStatus == nil || *p.HTTPStatus != 200 || p.Timings == nil {
			add("an answer that is not a failure has status 200 and timings")
		}
	} else if p.Code == "timeout" && p.HTTPStatus != nil {
		add("a timeout has no status")
	}
	return append(problems, timingProblems(p.Timings)...)
}

// timingProblems: the phases do not overlap, so they fit in the total.
func timingProblems(t *record.ProbeTimings) []string {
	if t == nil {
		return nil
	}
	sum := 0
	for name, ms := range map[string]*int{"dnsMs": t.DNSMs, "connectMs": t.ConnectMs, "tlsMs": t.TLSMs, "waitMs": t.WaitMs, "transferMs": t.TransferMs} {
		if ms == nil {
			continue
		}
		if *ms > t.TotalMs {
			return []string{fmt.Sprintf("timings.%s %d is longer than the attempt (%d)", name, *ms, t.TotalMs)}
		}
		sum += *ms
	}
	if sum > t.TotalMs {
		return []string{fmt.Sprintf("the phases add up to %d ms, more than the attempt (%d)", sum, t.TotalMs)}
	}
	return nil
}

// witnessLogProblems applies the rules of a v1 log check to what a witness
// did with a log, and one more: a root needs the size it belongs to.
func witnessLogProblems(name string, l record.WitnessLog) []string {
	if _, ok := cia.LevelOfCode("log:"+name, l.Code); !ok {
		return []string{fmt.Sprintf("%q is not a log code", l.Code)}
	}
	problems := logFieldProblems(&record.LogCheck{ID: "log:" + name, Code: l.Code, Status: l.Status, Size: l.Size, Record: l.Record, Finding: l.Finding})
	if l.Root != nil && l.Size == nil {
		problems = append(problems, "a root without the size it belongs to")
	}
	return problems
}
