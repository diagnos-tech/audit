package cia

import (
	"strings"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// SlotsPerDay is the number of five-minute slots in a UTC day.
const SlotsPerDay = 288

// DayInput is everything a day file is derived from.
type DayInput struct {
	Day   time.Time          // 00:00 UTC of the day
	Slots [SlotsPerDay]*Slot // nil: no run record in that slot
	// Colour applies the latest state of the incidents to the measurements.
	Colour Colourer
}

// cell is one slot of one service and dimension, as spans see it.
type cell struct {
	measured bool
	Cell
}

// BuildDay derives the day file (CONTRACTS §7.5). UpdatedAt is left empty: it
// is not part of the derivation.
func BuildDay(in DayInput) *record.CIADay {
	day := &record.CIADay{
		Schema: "cia-day/v1", Day: in.Day.Format(record.DayLayout),
		Services: map[string]record.CIADayLetters{}, Spans: []record.CIASpan{},
	}
	runs := make([]byte, SlotsPerDay)
	for i, s := range in.Slots {
		runs[i] = '0'
		if s != nil {
			runs[i] = '1'
		}
	}
	day.Runs = string(runs)

	for _, id := range Services(in.Slots[:]...) {
		var letters [3][]byte
		var cells [3][SlotsPerDay]cell
		for d := range letters {
			letters[d] = []byte(strings.Repeat("-", SlotsPerDay))
		}
		for i, s := range in.Slots {
			if s == nil {
				continue
			}
			dims, ok := s.Services[id]
			if !ok {
				continue
			}
			for d := range dims {
				c := cell{measured: true, Cell: in.Colour.Cell(id, d, s.Time, dims[d])}
				cells[d][i] = c
				letters[d][i] = Letter(c.Level)
			}
		}
		day.Services[id] = record.CIADayLetters{
			Availability: string(letters[0]), Integrity: string(letters[1]), Confidentiality: string(letters[2]),
			Latency: DayLatency(latencies(in.Slots[:], id)),
			Regions: dayRegions(in.Slots[:], id),
		}
		for d, name := range record.Dimensions {
			day.Spans = append(day.Spans, spans(id, name, cells[d][:])...)
		}
	}
	return day
}

// spans lists the maximal runs of consecutive measured slots that share a
// level other than ok, a code and the incident ids.
func spans(service, dimension string, cells []cell) []record.CIASpan {
	var out []record.CIASpan
	for i := 0; i < len(cells); {
		c := cells[i]
		if !c.measured || c.Level == record.LevelOK {
			i++
			continue
		}
		j := i
		for j+1 < len(cells) && same(c, cells[j+1]) {
			j++
		}
		ids := c.IDs
		if ids == nil {
			ids = []string{}
		}
		out = append(out, record.CIASpan{Service: service, Dimension: dimension, From: i, To: j,
			Level: c.Level, Code: c.Code, Incidents: ids})
		i = j + 1
	}
	return out
}

func same(a, b cell) bool {
	return b.measured && a.Result == b.Result && strings.Join(a.IDs, ",") == strings.Join(b.IDs, ",")
}

// latencies lists the healthz latency of a service in each slot of the day,
// nil where the slot has no run or no latency.
func latencies(slots []*Slot, service string) []*int {
	out := make([]*int, len(slots))
	for i, s := range slots {
		if s == nil {
			continue
		}
		if ms, ok := s.Latency[service]; ok {
			out[i] = &ms
		}
	}
	return out
}
