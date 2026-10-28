package check

import (
	"fmt"
	"strings"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// combinedProblems recomputes the combined verdicts of one service of a
// cia-run/v2 record from the witnesses' measurements and lists where the
// record's checks differ. The record states the combination so that a reader
// need not redo it; the rules are the ones in ARCH-V2 §7.1 (cia.Combine*), and
// nothing in the combined part may be better, or worse, than what the signed
// measurements allow.
func combinedProblems(v2 *record.CIARunV2, service string) []string {
	var problems []string
	svc := v2.Services[service]
	order := cia.Witnesses(sortedKeys(v2.Witnesses))
	readings := func(code func(m *record.Measured) string) []cia.Reading {
		out := make([]cia.Reading, len(order))
		for i, w := range order {
			out[i].Witness = w
			if m := v2.Witnesses[w].Measured; m != nil {
				out[i].Code = code(m)
			}
		}
		return out
	}
	wrong := func(id string, level, code string, want cia.Result) {
		if level != want.Level || code != want.Code {
			problems = append(problems, fmt.Sprintf("%s is %s/%s, the witnesses' measurements combine to %s/%s", id, level, code, want.Level, want.Code))
		}
	}
	for _, c := range svc.Availability.Checks {
		switch {
		case c.Healthz != nil:
			wrong(c.Healthz.ID, c.Healthz.Level, c.Healthz.Code,
				cia.CombineReachability("healthz", readings(func(m *record.Measured) string { return m.Probes[service].Code })))
		case c.Checkpoint != nil:
			log := strings.TrimPrefix(c.Checkpoint.ID, "checkpoint:")
			wrong(c.Checkpoint.ID, c.Checkpoint.Level, c.Checkpoint.Code,
				cia.CombineReachability("checkpoint", readings(func(m *record.Measured) string { return cia.CheckpointCode(m.Logs[log].Code) })))
		}
	}
	for _, c := range svc.Integrity.Checks {
		switch {
		case c.Log != nil:
			log := strings.TrimPrefix(c.Log.ID, "log:")
			wrong(c.Log.ID, c.Log.Level, c.Log.Code, cia.CombineEvidence(readings(func(m *record.Measured) string { return m.Logs[log].Code })))
			if want := evidenceFinding(v2, order, log); deref(c.Log.Finding) != deref(want) {
				problems = append(problems, fmt.Sprintf("%s names finding %q, the first witness with a finding or a halt names %q", c.Log.ID, deref(c.Log.Finding), deref(want)))
			}
		case c.Release != nil:
			problems = append(problems, releaseVantageProblems(v2, service, c.Release)...)
		}
	}
	return problems
}

// evidenceFinding is the finding of the first witness whose log code is finding
// or halted, nil when none is.
func evidenceFinding(v2 *record.CIARunV2, order []string, log string) *string {
	for _, w := range order {
		if m := v2.Witnesses[w].Measured; m != nil {
			if l := m.Logs[log]; l.Code == "finding" || l.Code == "halted" {
				return l.Finding
			}
		}
	}
	return nil
}

// releaseVantageProblems: the release of a service is judged from the primary
// witness's probe (verdicts are not regional), so it is not measured exactly
// when the primary's own probe of the service was not.
func releaseVantageProblems(v2 *record.CIARunV2, service string, rel *record.ReleaseCheck) []string {
	m := v2.Witnesses[record.WitnessEurope].Measured
	if m == nil {
		return nil
	}
	if (rel.Code == "vantage") != (m.Probes[service].Code == "vantage") {
		return []string{fmt.Sprintf("release is %s while the primary witness's probe is %s: the release is not measured exactly when the primary's own network failed", rel.Code, m.Probes[service].Code)}
	}
	return nil
}

// splitViewProblems: two witnesses that read different roots for one size of a
// log, in one run, prove that the log signed two trees. The record must say so:
// the log's evidence check fails and names a finding.
func splitViewProblems(v2 *record.CIARunV2) []string {
	var problems []string
	for _, log := range cia.SplitViews(v2) {
		named := false
		for _, svc := range v2.Services {
			for _, c := range svc.Integrity.Checks {
				if c.Log != nil && c.Log.ID == "log:"+log && c.Log.Level == record.LevelFail && c.Log.Finding != nil {
					named = true
				}
			}
		}
		if !named {
			problems = append(problems, fmt.Sprintf("the witnesses read different roots for one size of log %s, a split view, but its evidence check does not fail and name a finding", log))
		}
	}
	return problems
}

// v2FieldProblems are the field rules of the checks that exist only in
// cia-run/v2: a combined reachability check that is regional says which side
// failed, and a log check names a finding exactly when its code is one.
func v2FieldProblems(c record.CIACheck) []string {
	switch {
	case c.Healthz != nil && c.Code() == "regional" && c.Healthz.Error == nil,
		c.Checkpoint != nil && c.Code() == "regional" && c.Checkpoint.Error == nil:
		return []string{c.ID() + ": a regional result says which side failed (error)"}
	case c.Release != nil:
		return releaseFieldProblems(c.Release)
	case c.Log != nil && (c.Code() == "finding" || c.Code() == "halted") != (c.Log.Finding != nil):
		return []string{c.ID() + ": a log check names a finding exactly when its code is finding or halted"}
	}
	return nil
}
