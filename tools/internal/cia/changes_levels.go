package cia

import (
	"sort"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// debounce is how many consecutive recorded slots a new level must hold to be
// entered: three to get worse and two to get better for availability, so that
// the change coincides with an automatic incident opening and resolving; one
// for integrity, whose verdicts are written once (§8.1).
func debounce(dimension, from, to string) int {
	switch {
	case dimension == "integrity":
		return 1
	case rank[to] > rank[from]:
		return 3
	}
	return 2
}

// levelChanges finds, per service and for availability and integrity, the
// slots where the measured level enters a new debounced level. A slot that
// measured nothing neither counts nor interrupts, and the first slot sets the
// state without an event.
func levelChanges(runs []*record.CIARun) []record.CIAChange {
	var out []record.CIAChange
	for _, id := range serviceIDs(runs) {
		for _, dimension := range []string{"availability", "integrity"} {
			out = append(out, levelsOf(runs, id, dimension)...)
		}
	}
	return out
}

func levelsOf(runs []*record.CIARun, service, dimension string) []record.CIAChange {
	var out []record.CIAChange
	state, candidate := "", ""
	var count int
	var first time.Time
	for _, r := range runs {
		svc, ok := r.Services[service]
		if !ok {
			continue
		}
		level, at := svc.Dimension(dimension).Level, mustSlot(r.Slot)
		switch {
		case level == record.LevelNone:
			continue
		case state == "":
			state = level
			continue
		case level == state:
			candidate, count = "", 0
			continue
		case level != candidate:
			candidate, count, first = level, 0, at
		}
		if count++; count < debounce(dimension, state, candidate) {
			continue
		}
		e := event(Stamp(at)+"-"+service+"-"+dimension+"-level", at, first, "level-changed")
		e.Services, e.Categories = []string{service}, []string{map[string]string{"availability": "A", "integrity": "I"}[dimension]}
		e.Dimension, e.From, e.To = ptr(dimension), ptr(state), ptr(candidate)
		e.Summary = levelSummary(service, dimension, state, candidate)
		if failed, ok := regionalFailure(r, service); ok && dimension == "availability" {
			e.Summary = regionalSummary(e.Summary, failed)
		}
		out = append(out, e)
		state, candidate, count = candidate, "", 0
	}
	return out
}

// releaseAndFindingChanges finds the runs where a service's release check is
// verified with a digest not verified before, and where a log check names a
// finding not seen before.
func releaseAndFindingChanges(runs []*record.CIARun) []record.CIAChange {
	var out []record.CIAChange
	lastDigest := map[string]string{}
	seenFinding := map[string]bool{}
	for i, r := range runs {
		at := mustSlot(r.Slot)
		for _, id := range sortedIDs(r.Services) {
			for _, c := range r.Services[id].Integrity.Checks {
				if rel := c.Release; rel != nil && rel.Code == "verified" && rel.Digest != nil && rel.Verdict != nil {
					if i > 0 && *rel.Digest != lastDigest[id] {
						e := event(Stamp(at)+"-"+id+"-integrity-release", at, at, "release-verified")
						e.Services, e.Categories, e.Dimension = []string{id}, []string{"I"}, ptr("integrity")
						e.Summary = releaseSummary(id, deref(rel.Version))
						e.Links.Release = rel.Verdict
						out = append(out, e)
					}
					lastDigest[id] = *rel.Digest
				}
				if l := c.Log; l != nil && l.Finding != nil && !seenFinding[*l.Finding] {
					seenFinding[*l.Finding] = true
					e := event(Stamp(at)+"-"+id+"-integrity-finding", at, at, "finding")
					e.Services, e.Categories, e.Dimension = []string{id}, []string{"I"}, ptr("integrity")
					e.Summary = findingSummary(l.ID[len("log:"):])
					e.Links.Finding = l.Finding
					out = append(out, e)
				}
			}
		}
	}
	return out
}

// recordChanges finds the gaps and late data: three or more missing slots
// between two records, and the runs in which the auditor's own network failed.
// None of them is an outage of a service.
func recordChanges(runs []*record.CIARun) []record.CIAChange {
	var out []record.CIAChange
	vantage := false
	for i, r := range runs {
		at := mustSlot(r.Slot)
		if i > 0 {
			prev := mustSlot(runs[i-1].Slot)
			if missing := int(at.Sub(prev)/record.SlotLength) - 1; missing >= 3 {
				first := prev.Add(record.SlotLength)
				delayed := event(Stamp(first)+"-record-delayed", first, first, "record-delayed")
				delayed.Links.Record = nil // there is no record of a slot that is missing
				delayed.Summary = delayedSummary(missing * 5)
				resumed := event(Stamp(at)+"-record-resumed", at, at, "record-resumed")
				resumed.Summary = resumedSummary(missing * 5)
				out = append(out, delayed, resumed)
			}
		}
		if isVantageFailure(r) && !vantage {
			e := event(Stamp(at)+"-record-vantage", at, at, "vantage")
			e.Summary = vantageSummary()
			out = append(out, e)
		}
		vantage = isVantageFailure(r)
	}
	return out
}

// isVantageFailure says the run recorded its network checks as not measured
// because the auditor's own network failed (code vantage). In a cia-run/v2
// record it means that no witness measured anything: one witness whose own
// network failed while another measured is not news about the record.
func isVantageFailure(r *record.CIARun) bool {
	if r.V2 != nil {
		for _, svc := range r.Services {
			for _, c := range svc.Availability.Checks {
				if c.Healthz != nil && c.Healthz.Code != "vantage" {
					return false
				}
			}
		}
		return len(r.Services) > 0
	}
	for _, svc := range r.Services {
		for _, name := range record.Dimensions {
			for _, c := range svc.Dimension(name).Checks {
				if c.Code() == "vantage" {
					return true
				}
			}
		}
	}
	return false
}

func serviceIDs(runs []*record.CIARun) []string {
	seen := map[string]bool{}
	for _, r := range runs {
		for id := range r.Services {
			seen[id] = true
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
