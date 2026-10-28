package check

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// regionProblems checks the regions of one service of a day file on their own,
// without the run records: letters only where a run was recorded, a latency for
// exactly the slots that succeeded, and statistics, uptime and error counts that
// follow from the letters and latencies the region itself states. The run
// records then confirm the letters and latencies (compareRegions).
func regionProblems(service string, regions map[string]record.CIADayRegion, runs string) []string {
	var problems []string
	for _, w := range sortedKeys(regions) {
		for _, p := range oneRegionProblems(regions[w], runs) {
			problems = append(problems, fmt.Sprintf("%s region %s: %s", service, w, p))
		}
		if !witnessRE.MatchString(w) {
			problems = append(problems, fmt.Sprintf("%s has a region for %q, which is not a witness id", service, w))
		}
	}
	return problems
}

func oneRegionProblems(g record.CIADayRegion, runs string) []string {
	if len(g.Availability) != cia.SlotsPerDay || strings.Trim(g.Availability, "owf-") != "" {
		return []string{"availability is not 288 letters of o, w, f and -"}
	}
	if len(g.Latency.SlotsMs) != cia.SlotsPerDay {
		return []string{fmt.Sprintf("latency.slotsMs has %d entries, a day has %d", len(g.Latency.SlotsMs), cia.SlotsPerDay)}
	}
	up, measured, failed := 0, 0, 0
	for i, l := range []byte(g.Availability) {
		sample := g.Latency.SlotsMs[i] != nil
		switch {
		case l != '-' && runs[i] != '1':
			return []string{fmt.Sprintf("has %q in slot %d, where no run was recorded", l, i)}
		case sample != (l == 'o' || l == 'w'):
			return []string{fmt.Sprintf("slot %d is %q, but its latency is %s: exactly the probes that succeeded have one", i, l, msText(g.Latency.SlotsMs[i]))}
		}
		if l == 'o' || l == 'w' {
			up++
		}
		if l != '-' {
			measured++
		}
		if l == 'f' {
			failed++
		}
	}
	var problems []string
	if !reflect.DeepEqual(cia.LatencyOf(g.Latency.SlotsMs), g.Latency) {
		problems = append(problems, "latency statistics do not follow from its slotsMs")
	}
	if g.Uptime.Up != up || g.Uptime.Measured != measured {
		problems = append(problems, fmt.Sprintf("uptime %d of %d does not follow from its letters (%d of %d)", g.Uptime.Up, g.Uptime.Measured, up, measured))
	}
	if g.Errors.Total() != failed {
		problems = append(problems, fmt.Sprintf("%d errors by class, but %d failed slots", g.Errors.Total(), failed))
	}
	if g.Retries > measured {
		problems = append(problems, fmt.Sprintf("%d retries in %d measured slots", g.Retries, measured))
	}
	return problems
}

// compareRegions lists how the regions of a day file differ from the derived
// ones in the slots that have a run record (the others are not in these files).
func compareRegions(id string, want, got map[string]record.CIADayRegion, present [cia.SlotsPerDay]bool) []string {
	var diffs []string
	for _, w := range sortedKeys(want) {
		g, ok := got[w]
		if !ok {
			diffs = append(diffs, fmt.Sprintf("%s has no region %s, the run records give one", id, w))
			continue
		}
		if len(g.Availability) != cia.SlotsPerDay || len(g.Latency.SlotsMs) != cia.SlotsPerDay {
			continue // reported by regionProblems
		}
		for i, p := range present {
			switch {
			case !p:
			case want[w].Availability[i] != g.Availability[i]:
				diffs = append(diffs, fmt.Sprintf("%s region %s slot %d is %q, the run records give %q", id, w, i, g.Availability[i], want[w].Availability[i]))
			case !equalMs(want[w].Latency.SlotsMs[i], g.Latency.SlotsMs[i]):
				diffs = append(diffs, fmt.Sprintf("%s region %s latency in slot %d is %s, the run records give %s", id, w, i, msText(g.Latency.SlotsMs[i]), msText(want[w].Latency.SlotsMs[i])))
			}
		}
	}
	for _, w := range sortedKeys(got) {
		if _, ok := want[w]; !ok {
			diffs = append(diffs, fmt.Sprintf("%s has a region %s that no run record names", id, w))
		}
	}
	return diffs
}

func claimedRegionSince(l *record.CIALatest, service, witness string) (time.Time, bool) {
	region, ok := l.Services[service].Availability.Regions[witness]
	if !ok {
		return time.Time{}, false
	}
	t, err := record.ParseTime(region.Since)
	return t, err == nil
}

func claimedWitnessSince(l *record.CIALatest, witness string) (time.Time, bool) {
	w, ok := l.Witnesses[witness]
	if !ok {
		return time.Time{}, false
	}
	t, err := record.ParseTime(w.Since)
	return t, err == nil
}

// dropSummaryRegions blanks the regions of a summary: while the latest run is a
// cia-run/v1 record, a summary does not have to carry them.
func dropSummaryRegions(s *record.CIASummary, drop bool) {
	if !drop {
		return
	}
	for id, svc := range s.Services {
		svc.Regions = nil
		s.Services[id] = svc
	}
}

// hasV2 says a cia-run/v2 record of the day is among the run records.
func hasV2(f *ciaFacts, day time.Time) bool {
	for i := 0; i < cia.SlotsPerDay; i++ {
		if run, ok := f.byTime[day.Add(time.Duration(i)*record.SlotLength)]; ok && run.V2 != nil {
			return true
		}
	}
	return false
}

func hasRegions(d *record.CIADay) bool {
	for _, s := range d.Services {
		if len(s.Regions) > 0 {
			return true
		}
	}
	return false
}

func dropDayRegions(d *record.CIADay) {
	for id, s := range d.Services {
		s.Regions = nil
		d.Services[id] = s
	}
}
