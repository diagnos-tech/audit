package cia

import (
	"slices"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// NearestRank is the p-th percentile (1 to 100) of the values by the nearest
// rank method: the value at 1-based position ceil(p*n/100) of the n sorted
// values. ok is false when there are no values.
func NearestRank(values []int, p int) (value int, ok bool) {
	if len(values) == 0 {
		return 0, false
	}
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	rank := (p*len(sorted) + 99) / 100
	return sorted[max(rank, 1)-1], true
}

// DayLatency is the latency entry of a day file for the latency of one
// service in each slot of the day (nil where there is none).
func DayLatency(slotsMs []*int) *record.CIALatency {
	var values []int
	for _, ms := range slotsMs {
		if ms != nil {
			values = append(values, *ms)
		}
	}
	l := &record.CIALatency{Samples: len(values), SlotsMs: slotsMs}
	if p50, ok := NearestRank(values, 50); ok {
		p95, _ := NearestRank(values, 95)
		l.P50Ms, l.P95Ms = &p50, &p95
	}
	return l
}
