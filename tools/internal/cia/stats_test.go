package cia

import (
	"reflect"
	"testing"
)

func ptrs(v ...int) []*int {
	out := make([]*int, len(v))
	for i := range v {
		if v[i] >= 0 {
			out[i] = &v[i]
		}
	}
	return out
}

func val(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

// Rank is the nearest rank for 1 to 100, the minimum for 0, and nothing for no
// values; the positions are worked out by hand.
func TestRank(t *testing.T) {
	for _, c := range []struct {
		name string
		n, p int
		want int // the position of the value, 0 for none
	}{
		{"nothing", 0, 50, 0},
		{"p0 is the minimum", 7, 0, 1},
		{"p100 is the maximum", 7, 100, 7},
		{"one value", 1, 99, 1},
		{"median of two", 2, 50, 1},
		{"p75 of four", 4, 75, 3},
		{"p90 of ten", 10, 90, 9},
		{"p95 of 19 is the maximum", 19, 95, 19},
		{"p95 of 20", 20, 95, 19},
		{"p99 of 99 is the maximum", 99, 99, 99},
		{"p99 of 100", 100, 99, 99},
		{"p99 of 288", 288, 99, 286},
		{"p50 of 288", 288, 50, 144},
	} {
		got, ok := Rank(ramp(c.n), c.p)
		if c.want == 0 {
			if ok {
				t.Errorf("%s: a percentile of nothing = %d", c.name, got)
			}
			continue
		}
		if !ok || got != c.want*10 {
			t.Errorf("%s: got %d, want position %d (value %d)", c.name, got, c.want, c.want*10)
		}
	}
}

// The mean rounds half up, in integers: (2*sum+n) div (2*n).
func TestMean(t *testing.T) {
	for _, c := range []struct {
		in   []int
		want int
		ok   bool
	}{
		{nil, 0, false},
		{[]int{7}, 7, true},
		{[]int{1, 2}, 2, true},            // 1.5 rounds up
		{[]int{1, 1, 2}, 1, true},         // 1.33
		{[]int{1, 2, 2}, 2, true},         // 1.67
		{[]int{10, 20, 30, 41}, 25, true}, // 25.25
		{[]int{0, 0, 0, 1}, 0, true},      // 0.25
		{[]int{0, 1}, 1, true},            // 0.5 rounds up
	} {
		got, ok := Mean(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("Mean(%v) = %d %v, want %d %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// Failures are not latency samples: nil slots do not count and do not move the
// percentiles.
func TestLatencyOf(t *testing.T) {
	l := LatencyOf(ptrs(300, -1, 100, -1, 200, -1))
	got := map[string]any{"samples": l.Samples, "min": val(l.MinMs), "p50": val(l.P50Ms), "p75": val(l.P75Ms), "p90": val(l.P90Ms),
		"p95": val(l.P95Ms), "p99": val(l.P99Ms), "max": val(l.MaxMs), "mean": val(l.MeanMs)}
	want := map[string]any{"samples": 3, "min": 100, "p50": 200, "p75": 300, "p90": 300, "p95": 300, "p99": 300, "max": 300, "mean": 200}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
	if len(l.SlotsMs) != 6 {
		t.Errorf("slotsMs has %d entries, the input has 6", len(l.SlotsMs))
	}
	empty := LatencyOf(ptrs(-1, -1))
	if empty.Samples != 0 || empty.MinMs != nil || empty.P99Ms != nil || empty.MeanMs != nil {
		t.Errorf("a day without a sample has statistics: %+v", empty)
	}
}

// Small samples are as the spec says: with fewer than 100 samples p99 is the
// maximum, and with fewer than 20 so is p95.
func TestSmallSamplesSaturate(t *testing.T) {
	for _, c := range []struct {
		n                  int
		p95IsMax, p99IsMax bool
	}{{1, true, true}, {19, true, true}, {20, false, true}, {99, false, true}, {100, false, false}, {288, false, false}} {
		slots := make([]*int, 0, c.n)
		for _, v := range ramp(c.n) {
			slots = append(slots, &v)
		}
		l := LatencyOf(slots)
		if got := *l.P95Ms == *l.MaxMs; got != c.p95IsMax {
			t.Errorf("n=%d: p95 equals the maximum = %v, want %v", c.n, got, c.p95IsMax)
		}
		if got := *l.P99Ms == *l.MaxMs; got != c.p99IsMax {
			t.Errorf("n=%d: p99 equals the maximum = %v, want %v", c.n, got, c.p99IsMax)
		}
	}
}

func TestPhaseOf(t *testing.T) {
	s := PhaseOf([]int{4, 4, 5, 20})
	if val(s.MeanMs) != 8 || val(s.P50Ms) != 4 || val(s.P95Ms) != 20 {
		t.Errorf("got mean %v p50 %v p95 %v", val(s.MeanMs), val(s.P50Ms), val(s.P95Ms))
	}
	if e := PhaseOf(nil); e.MeanMs != nil || e.P50Ms != nil || e.P95Ms != nil {
		t.Errorf("a phase that was never measured has statistics: %+v", e)
	}
}
