package cia

import (
	"slices"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// Rank is the nearest-rank percentile p (0 to 100) of the values: the value at
// 1-based position ceil(p*n/100) of the n sorted values, the minimum for p 0.
// ok is false when there are no values. Integers only, no interpolation, so
// that the page, the verifier and a shell one-liner agree byte for byte.
func Rank(values []int, p int) (value int, ok bool) {
	if len(values) == 0 {
		return 0, false
	}
	if p == 0 {
		return slices.Min(values), true
	}
	return NearestRank(values, p)
}

// Mean is the mean of the values rounded half up, in integers: (2*sum+n) div
// (2*n). ok is false when there are no values.
func Mean(values []int) (mean int, ok bool) {
	if len(values) == 0 {
		return 0, false
	}
	sum := 0
	for _, v := range values {
		sum += v
	}
	return (2*sum + len(values)) / (2 * len(values)), true
}

// LatencyOf computes the statistics of a witness's day from the latency of
// each of its slots (nil where the probe did not succeed). Timeouts and other
// failures are not latency samples: counting a timeout as its deadline would
// make availability bleed into latency, and every high percentile the
// deadline.
func LatencyOf(slotsMs []*int) record.LatencyStats {
	values := present(slotsMs)
	l := record.LatencyStats{Samples: len(values), SlotsMs: slotsMs}
	for _, f := range []struct {
		dst *(*int)
		p   int
	}{{&l.MinMs, 0}, {&l.P50Ms, 50}, {&l.P75Ms, 75}, {&l.P90Ms, 90}, {&l.P95Ms, 95}, {&l.P99Ms, 99}, {&l.MaxMs, 100}} {
		if v, ok := Rank(values, f.p); ok {
			*f.dst = &v
		}
	}
	if v, ok := Mean(values); ok {
		l.MeanMs = &v
	}
	return l
}

// PhaseOf is the mean, the median and the 95th percentile of one timing phase
// over the probes where it was measured.
func PhaseOf(values []int) record.PhaseStats {
	var s record.PhaseStats
	if v, ok := Mean(values); ok {
		s.MeanMs = &v
	}
	if v, ok := Rank(values, 50); ok {
		s.P50Ms = &v
	}
	if v, ok := Rank(values, 95); ok {
		s.P95Ms = &v
	}
	return s
}

func present(list []*int) []int {
	var out []int
	for _, v := range list {
		if v != nil {
			out = append(out, *v)
		}
	}
	return out
}
