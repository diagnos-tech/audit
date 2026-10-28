package cia

import (
	"sort"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// BuildIncidentList derives data/v1/cia/incidents.json (INCIDENTS-CONTRACT
// §6): the declared incidents of the snapshot in force (snapshotPath and
// snapshot are nil when none was written) and the automatic ones in the state
// of their latest event, newest start first, ties by id.
func BuildIncidentList(snapshotPath string, snapshot *record.CIAIncidents, events map[string][]record.CIAIncidentEvent) *record.CIAIncidentList {
	list := &record.CIAIncidentList{Schema: "cia-incident-list/v1", Incidents: []record.CIAListItem{}}
	var declared []record.CIAIncident
	if snapshot != nil {
		list.Declared = &record.CIAListDeclared{Snapshot: snapshotPath, Commit: snapshot.Source.Commit, ReadAt: snapshot.ReadAt}
		declared = snapshot.Incidents
		for i := range declared {
			list.Incidents = append(list.Incidents, record.CIAListItem{Declared: &declared[i]})
		}
	}
	for _, id := range sortedIDs(events) {
		list.Incidents = append(list.Incidents, record.CIAListItem{Auto: autoState(events[id], declared)})
	}
	sort.SliceStable(list.Incidents, func(i, j int) bool {
		a, b := list.Incidents[i], list.Incidents[j]
		if a.StartedAt() != b.StartedAt() {
			return a.StartedAt() > b.StartedAt()
		}
		return a.ID() < b.ID()
	})
	return list
}

// autoState folds the events of one automatic incident (ordered by seq).
func autoState(events []record.CIAIncidentEvent, declared []record.CIAIncident) *record.CIAAutoIncident {
	first, last := events[0], events[len(events)-1]
	a := &record.CIAAutoIncident{
		ID: last.ID, Source: "auditor", Categories: last.Categories, Services: last.Services, Severity: last.Severity,
		Status: "open", OpenedAt: first.At, StartedAt: last.StartedAt, ResolvedAt: last.ResolvedAt, UpdatedAt: last.At,
		Reasons: last.Reasons, Events: len(events),
		LastEvent: record.CIAIncidentEventPath(last.ID, last.Seq, mustSlot(last.At)), Postmortems: []string{},
	}
	if last.ResolvedAt != nil {
		a.Status = "resolved"
	}
	for _, d := range declared {
		if d.Relates != nil && *d.Relates == last.ID {
			a.Postmortems = append(a.Postmortems, d.ID)
		}
	}
	sort.Strings(a.Postmortems)
	return a
}
