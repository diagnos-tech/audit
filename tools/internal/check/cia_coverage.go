package check

import (
	"fmt"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// coverageReport is check 6 of INCIDENTS-CONTRACT §5: a failure the auditor
// did not turn into an incident is detectable. Every run of at least three
// consecutive recorded slots in which a service's measured availability is
// fail must lie inside an availability incident of that service, and every
// recorded slot in which its measured integrity is fail inside an integrity
// incident. Slots that measured nothing neither count nor interrupt a run, and
// a failure that reaches back to the oldest record of a slice may have an
// incident that started before it.
func coverageReport(f *ciaFacts, set *eventSet, complete bool) *Report {
	r := &Report{Subject: "incident coverage"}
	var gaps []string
	for _, service := range cia.Services(slotPtrs(f.chain)...) {
		for _, dimension := range []string{"availability", "integrity"} {
			gaps = append(gaps, uncovered(f, set, service, dimension, complete)...)
		}
	}
	if len(gaps) > 0 {
		r.fail("coverage", "%s", gaps[0])
		return r
	}
	r.pass("coverage", "every failure of %d recorded slots is inside an incident", len(f.chain))
	return r
}

func slotPtrs(chain []cia.Slot) []*cia.Slot {
	out := make([]*cia.Slot, len(chain))
	for i := range chain {
		out[i] = &chain[i]
	}
	return out
}

func uncovered(f *ciaFacts, set *eventSet, service, dimension string, complete bool) []string {
	category := cia.CategoryOf(dimension)
	var incidents []cia.Incident
	for _, id := range sortedKeys(set.byID) {
		if latest := set.byID[id][len(set.byID[id])-1]; latest.Services[0] == service && latest.Categories[0] == category {
			inc, _ := cia.FromEvents(map[string][]record.CIAIncidentEvent{id: set.byID[id]})
			incidents = append(incidents, inc...)
		}
	}
	covers := func(from, to time.Time) bool { // [from, to) is inside one incident
		for _, in := range incidents {
			if !in.Start.After(from) && (in.End == nil || !in.End.Before(to)) {
				return true
			}
		}
		return false
	}
	var gaps []string
	var run []time.Time // the failing slots in a row, the slots that measured nothing left out
	flush := func() {
		oldest := !complete && len(run) > 0 && run[0].Equal(f.chain[0].Time)
		if len(run) >= 3 && !oldest && !covers(run[0], run[len(run)-1].Add(record.SlotLength)) {
			gaps = append(gaps, fmt.Sprintf("%s of %s failed from %s for %d recorded slots, but no %s incident of the service covers it",
				dimension, service, record.FormatTime(run[0]), len(run), dimension))
		}
		run = nil
	}
	i := cia.DimIndex(dimension)
	for _, s := range f.chain {
		dims, ok := s.Services[service]
		switch {
		case !ok || dims[i].Level == record.LevelNone:
			continue
		case dims[i].Level == record.LevelFail && dimension == "integrity":
			if oldest := !complete && s.Time.Equal(f.chain[0].Time); !oldest && !covers(s.Time, s.Time.Add(record.SlotLength)) {
				gaps = append(gaps, fmt.Sprintf("integrity of %s failed at %s, but no integrity incident of the service covers it", service, record.FormatTime(s.Time)))
			}
		case dims[i].Level == record.LevelFail:
			run = append(run, s.Time)
		default:
			flush()
		}
	}
	flush()
	return gaps
}

// relatesReportProblems is check 7: every declared incident that relates to an
// automatic one names an incident that has an opened event.
func relatesReportProblems(newest *record.CIAIncidents, set *eventSet) []string {
	var problems []string
	if newest == nil {
		return nil
	}
	for _, in := range newest.Incidents {
		if in.Relates == nil {
			continue
		}
		if events := set.byID[*in.Relates]; len(events) == 0 || events[0].Type != "opened" {
			problems = append(problems, fmt.Sprintf("%s relates to %s, which no event opened", in.ID, *in.Relates))
		}
	}
	return problems
}
