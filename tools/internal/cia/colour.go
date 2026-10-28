package cia

import (
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// Cell is a service's dimension in one slot, as the views show it: the level
// and code after the incidents have coloured the measurement, and the
// incidents behind the colour.
type Cell struct {
	Result
	IDs []string
}

// Colourer applies the state of the incidents to measurements
// (INCIDENTS-CONTRACT §3).
type Colourer struct {
	Incidents Incidents
	// HaveSnapshot says a declared snapshot exists. While none does, the
	// confidentiality a run measured stands.
	HaveSnapshot bool
}

// Cell colours the measured result m of dimension dim (an index of
// record.Dimensions) of the service in the slot at t.
//
// Confidentiality is only what the incidents with category C say; a run that
// could not read an incident file (code invalid) keeps its level when that is at
// least as bad. Availability and integrity are the worse of the measurement
// and the incidents; the code is the measurement's unless the incidents are
// worse, when it is incident-low or incident-high. Where no incident affects
// the slot the measurement is left alone, so a slot that measured nothing
// stays grey.
func (c Colourer) Cell(service string, dim int, t time.Time, m Result) Cell {
	level, ids := c.Incidents.Level(service, record.Dimensions[dim], t)
	incident := Result{Level: level, Code: map[string]string{record.LevelOK: "clear", record.LevelWarn: "incident-low", record.LevelFail: "incident-high"}[level]}
	switch {
	case dim == 2 && !c.HaveSnapshot:
		return Cell{m, ids}
	case dim == 2:
		if m.Code == "invalid" && rank[m.Level] >= rank[incident.Level] {
			return Cell{m, ids}
		}
		return Cell{incident, ids}
	case level == record.LevelOK:
		return Cell{m, ids}
	case rank[m.Level] >= rank[level]:
		return Cell{Result{Level: m.Level, Code: m.Code}, ids}
	}
	return Cell{incident, ids}
}
