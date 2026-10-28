package cia

import (
	"fmt"
	"sort"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// Result is the outcome of one dimension of one service in one run: its level
// and the code of the first check, in contract order, that has that level.
type Result struct{ Level, Code string }

// Dims holds the results of the three dimensions, in record.Dimensions order.
type Dims [3]Result

// Slot is a run as the projections need it.
type Slot struct {
	Time     time.Time
	Services map[string]Dims
	// Latency is the latencyMs of each service's healthz check, for the
	// services where it is not null.
	Latency map[string]int
}

// FromRun extracts a Slot from a run record, trusting the levels the record
// states (the checks in `verify cia` confirm them).
func FromRun(r *record.CIARun) (Slot, error) {
	t, err := record.ParseTime(r.Slot)
	if err != nil {
		return Slot{}, err
	}
	s := Slot{Time: t, Services: map[string]Dims{}, Latency: map[string]int{}}
	for id, svc := range r.Services {
		for _, c := range svc.Availability.Checks {
			if c.Healthz != nil && c.Healthz.LatencyMs != nil {
				s.Latency[id] = *c.Healthz.LatencyMs
			}
		}
		var d Dims
		for i, name := range record.Dimensions {
			dim := svc.Dimension(name)
			d[i] = Result{Level: dim.Level, Code: FirstCode(dim)}
		}
		s.Services[id] = d
	}
	return s, nil
}

// FirstCode is the code of the first check of the dimension whose level is
// the dimension's level.
func FirstCode(d record.CIADimension) string {
	for _, c := range d.Checks {
		if c.Level() == d.Level {
			return c.Code()
		}
	}
	return ""
}

// DimIndex is the position of a dimension name in record.Dimensions.
func DimIndex(name string) int {
	for i, d := range record.Dimensions {
		if d == name {
			return i
		}
	}
	panic(fmt.Sprintf("cia: unknown dimension %q", name))
}

// Since returns the start of the unbroken sequence of runs, ending at the last
// one of chain (oldest first, chain-consecutive), in which the service's
// dimension, coloured by the incidents, had the same level as in the last run.
// reachedStart is true when the sequence goes back to chain[0], so older runs,
// if any, may extend it. Gaps in time do not break a sequence; a run without
// the service does.
func Since(chain []Slot, c Colourer, service, dimension string) (since time.Time, reachedStart bool) {
	i := DimIndex(dimension)
	level := func(s Slot) (string, bool) {
		dims, ok := s.Services[service]
		return c.Cell(service, i, s.Time, dims[i]).Level, ok
	}
	last := len(chain) - 1
	want, _ := level(chain[last])
	start := last
	for start > 0 {
		if got, ok := level(chain[start-1]); !ok || got != want {
			return chain[start].Time, false
		}
		start--
	}
	return chain[0].Time, true
}

// Services returns the sorted service ids present in any of the slots.
func Services(slots ...*Slot) []string {
	seen := map[string]bool{}
	for _, s := range slots {
		if s == nil {
			continue
		}
		for id := range s.Services {
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

// mustSlot parses a time that has already been validated.
func mustSlot(s string) time.Time {
	t, err := record.ParseTime(s)
	if err != nil {
		panic("cia: unparsed time " + s)
	}
	return t
}
