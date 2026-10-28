package cia

import (
	"sort"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// Incident is a published incident, declared or automatic, in its latest
// state. Colours are a function of that state, never of what was known when a
// run happened (INCIDENTS-CONTRACT §2).
type Incident struct {
	ID         string
	Auto       bool
	Services   []string
	Categories []string // C, I, A
	Level      string   // warn for low and medium, fail for high and critical
	Start      time.Time
	End        *time.Time // nil: not resolved
}

// Incidents is the set of published incidents.
type Incidents []Incident

// LevelOfSeverity is the level an incident of that severity gives.
func LevelOfSeverity(severity string) string {
	if severity == "high" || severity == "critical" {
		return record.LevelFail
	}
	return record.LevelWarn
}

// CategoryOf is the incident category that colours a dimension.
func CategoryOf(dimension string) string {
	return map[string]string{"confidentiality": "C", "integrity": "I", "availability": "A"}[dimension]
}

// FromSnapshot lists the declared incidents of a snapshot (it holds only the
// published ones).
func FromSnapshot(s *record.CIAIncidents) (Incidents, error) {
	var out Incidents
	for _, in := range s.Incidents {
		inc, err := newIncident(in.ID, false, in.Services, in.Categories, in.Severity, in.StartedAt, in.ResolvedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, inc)
	}
	return out, nil
}

// FoldEvents groups the events of automatic incidents by id, each group
// ordered by seq.
func FoldEvents(events []record.CIAIncidentEvent) map[string][]record.CIAIncidentEvent {
	byID := map[string][]record.CIAIncidentEvent{}
	for _, e := range events {
		byID[e.ID] = append(byID[e.ID], e)
	}
	for _, list := range byID {
		sort.Slice(list, func(i, j int) bool { return list[i].Seq < list[j].Seq })
	}
	return byID
}

// FromEvents lists the automatic incidents in the state of their latest event.
func FromEvents(byID map[string][]record.CIAIncidentEvent) (Incidents, error) {
	var out Incidents
	for _, id := range sortedIDs(byID) {
		e := byID[id][len(byID[id])-1]
		inc, err := newIncident(e.ID, true, e.Services, e.Categories, e.Severity, e.StartedAt, e.ResolvedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, inc)
	}
	return out, nil
}

func newIncident(id string, auto bool, services, categories []string, severity, started string, resolved *string) (Incident, error) {
	start, err := record.ParseTime(started)
	if err != nil {
		return Incident{}, err
	}
	inc := Incident{ID: id, Auto: auto, Services: services, Categories: categories, Level: LevelOfSeverity(severity), Start: start}
	if resolved != nil {
		end, err := record.ParseTime(*resolved)
		if err != nil {
			return Incident{}, err
		}
		inc.End = &end
	}
	return inc, nil
}

// Affecting lists, sorted by id, the incidents that affect the service in the
// dimension in the slot [t, t+5min): the service is one of theirs, the
// dimension's category is among theirs, they started before the slot ends and
// are unresolved or resolved after the slot starts.
func (is Incidents) Affecting(service, dimension string, t time.Time) []Incident {
	category := CategoryOf(dimension)
	var out []Incident
	for _, in := range is {
		if !contains(in.Services, service) || !contains(in.Categories, category) || !in.Start.Before(t.Add(record.SlotLength)) {
			continue
		}
		if in.End == nil || in.End.After(t) {
			out = append(out, in)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Level is the worst level of the affecting incidents (ok when there are none)
// and their ids, sorted, never nil.
func (is Incidents) Level(service, dimension string, t time.Time) (string, []string) {
	level, ids := record.LevelOK, []string{}
	for _, in := range is.Affecting(service, dimension, t) {
		ids = append(ids, in.ID)
		level = Worst(level, in.Level)
	}
	return level, ids
}

// OpenIDs lists the incidents that are not resolved, newest start first, ties
// by id.
func (is Incidents) OpenIDs() []string {
	var open []Incident
	for _, in := range is {
		if in.End == nil {
			open = append(open, in)
		}
	}
	return newestFirst(open)
}

func newestFirst(list []Incident) []string {
	sort.Slice(list, func(i, j int) bool {
		if !list[i].Start.Equal(list[j].Start) {
			return list[i].Start.After(list[j].Start)
		}
		return list[i].ID < list[j].ID
	})
	ids := []string{}
	for _, in := range list {
		ids = append(ids, in.ID)
	}
	return ids
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sortedIDs[V any](m map[string]V) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
