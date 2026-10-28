package cia

import (
	"slices"
	"testing"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

func ramp(n int) []int {
	v := make([]int, n)
	for i := range v {
		v[i] = (i + 1) * 10 // 10, 20, ... n*10: the value at position k is k*10
	}
	return v
}

// The nearest rank is the value at position ceil(p*n/100), one-based.
func TestNearestRank(t *testing.T) {
	for _, c := range []struct {
		n        int
		p50, p95 int // positions
	}{
		{1, 1, 1}, {2, 1, 2}, {3, 2, 3}, {19, 10, 19}, {20, 10, 19}, {21, 11, 20}, {100, 50, 95}, {101, 51, 96},
	} {
		v := ramp(c.n)
		if got, ok := NearestRank(v, 50); !ok || got != c.p50*10 {
			t.Errorf("n=%d p50 = %d, want position %d", c.n, got, c.p50)
		}
		if got, ok := NearestRank(v, 95); !ok || got != c.p95*10 {
			t.Errorf("n=%d p95 = %d, want position %d", c.n, got, c.p95)
		}
	}
	if _, ok := NearestRank(nil, 95); ok {
		t.Error("the percentile of nothing exists")
	}
	if v, _ := NearestRank([]int{5}, 100); v != 5 {
		t.Errorf("p100 of one value = %d", v)
	}
}

func TestNearestRankDoesNotNeedSortedInputOrChangeIt(t *testing.T) {
	in := []int{90, 10, 50, 30, 70}
	if got, _ := NearestRank(in, 50); got != 50 {
		t.Errorf("median of %v = %d", in, got)
	}
	if !slices.Equal(in, []int{90, 10, 50, 30, 70}) {
		t.Errorf("the input was sorted in place: %v", in)
	}
}

// slots makes a day's worth of latencies: the given values in the first slots,
// nil (no run, or no latency) elsewhere; a negative value is a nil entry.
func slots(values ...int) []*int {
	out := make([]*int, SlotsPerDay)
	for i, v := range values {
		if v >= 0 {
			out[i] = &values[i]
		}
	}
	return out
}

func TestDayLatency(t *testing.T) {
	l := DayLatency(slots(300, 100, -1, 200, 400))
	if l.Samples != 4 || *l.P50Ms != 200 || *l.P95Ms != 400 {
		t.Errorf("%+v", l)
	}
	if len(l.SlotsMs) != SlotsPerDay || l.SlotsMs[2] != nil || *l.SlotsMs[3] != 200 {
		t.Errorf("slotsMs %v", l.SlotsMs[:5])
	}
	none := DayLatency(slots())
	if none.Samples != 0 || none.P50Ms != nil || none.P95Ms != nil || len(none.SlotsMs) != SlotsPerDay {
		t.Errorf("no samples: %+v", none)
	}
}

func withLatency(i int, service string, ms ...int) *Slot {
	s := slotWith(i, map[string]Dims{service: okDims})
	if len(ms) > 0 {
		s.Latency = map[string]int{service: ms[0]}
	}
	return s
}

// Samples are the runs that have a latency: a timeout has none, a slot
// without a run is not a sample.
func TestBuildDayLatencyCountsOnlyRunsWithALatency(t *testing.T) {
	in := DayInput{Day: day}
	in.Slots[0] = withLatency(0, "vault", 100)
	in.Slots[1] = withLatency(1, "vault", 200)
	in.Slots[2] = withLatency(2, "vault") // timed out: no latency
	in.Slots[3] = withLatency(3, "vault", 300)
	in.Slots[4] = withLatency(4, "sign") // a service with a run but never a latency
	got := BuildDay(in)
	v := got.Services["vault"].Latency
	if v == nil || v.Samples != 3 || *v.P50Ms != 200 || *v.P95Ms != 300 {
		t.Errorf("vault %+v", v)
	}
	if v.SlotsMs[0] == nil || *v.SlotsMs[0] != 100 || v.SlotsMs[2] != nil || *v.SlotsMs[3] != 300 || v.SlotsMs[4] != nil {
		t.Errorf("slotsMs of vault %v", v.SlotsMs[:5])
	}
	s := got.Services["sign"].Latency
	if s == nil || s.Samples != 0 || s.P50Ms != nil || s.P95Ms != nil {
		t.Errorf("sign %+v", s)
	}
}

func TestSummaryP95FollowsTheDayFiles(t *testing.T) {
	days := map[string]*record.CIADay{}
	for k, ms := range map[int][]int{0: {100, 120, 900}, 1: nil} {
		d := day.AddDate(0, 0, -k)
		in := DayInput{Day: d}
		for i, v := range ms {
			s := withLatency(i, "vault", v)
			s.Time = d.Add(time.Duration(i) * record.SlotLength)
			in.Slots[i] = s
		}
		if ms == nil { // a run without a latency
			in.Slots[0] = &Slot{Time: d, Services: map[string]Dims{"vault": okDims}}
		}
		days[d.Format(record.DayLayout)] = BuildDay(in)
	}
	// day-2 has no file at all.
	p95 := BuildSummary(days, day.AddDate(0, 0, -2), day, "u").Services["vault"].P95Ms
	if len(p95) != 90 {
		t.Fatalf("%d entries", len(p95))
	}
	if p95[89] == nil || *p95[89] != 900 {
		t.Errorf("last day %v, want 900", p95[89])
	}
	if p95[88] != nil {
		t.Errorf("a day with no samples is null, got %d", *p95[88])
	}
	if p95[87] != nil || p95[0] != nil {
		t.Error("a day with no file is null")
	}
}
