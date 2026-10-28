package cia

import (
	"fmt"
	"reflect"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// autoIncidentChanges turns the events of automatic incidents into change
// events: the same id as the event fact, at the slot of the run that wrote it.
func autoIncidentChanges(events []record.CIAIncidentEvent) []record.CIAChange {
	var out []record.CIAChange
	for _, e := range events {
		at := mustSlot(e.At)
		verb := e.Type // opened, updated, resolved
		c := event(fmt.Sprintf("%s-%d", e.ID, e.Seq), at, at, "incident-"+verb)
		c.Services, c.Categories = e.Services, e.Categories
		c.Summary = autoIncidentSummary(verb, e)
		c.Links = record.CIAChangeLinks{Record: ptr(e.Run), Incident: ptr(e.ID)}
		out = append(out, c)
	}
	return out
}

// declaredIncidentChanges compares each snapshot with the one before: a
// declared incident that appears is opened; one that disappears is removed;
// one whose resolvedAt went from null to a time is resolved, whatever else
// changed; one that changed otherwise is updated.
func declaredIncidentChanges(snapshots []Snapshot) []record.CIAChange {
	var out []record.CIAChange
	prev := map[string]record.CIAIncident{}
	for _, s := range snapshots {
		now := map[string]record.CIAIncident{}
		for _, in := range s.Content.Incidents {
			now[in.ID] = in
			before, existed := prev[in.ID]
			switch {
			case !existed:
				out = append(out, declaredEvent("opened", "declared", s.Slot, in))
			case before.ResolvedAt == nil && in.ResolvedAt != nil:
				out = append(out, declaredEvent("resolved", "resolved", s.Slot, in))
			case !reflect.DeepEqual(before, in):
				out = append(out, declaredEvent("updated", "updated", s.Slot, in))
			}
		}
		for _, id := range sortedIDs(prev) {
			if _, still := now[id]; !still {
				out = append(out, declaredEvent("removed", "removed", s.Slot, prev[id]))
			}
		}
		prev = now
	}
	return out
}

// declaredEvent is the change event of a declared incident at a snapshot.
// kind is the suffix of incident-<kind>; verb picks the summary words.
func declaredEvent(kind, verb string, slot time.Time, in record.CIAIncident) record.CIAChange {
	c := event(in.ID+"-"+Stamp(slot), slot, slot, "incident-"+kind)
	c.Services, c.Categories = in.Services, in.Categories
	c.Summary = declaredIncidentSummary(verb, in.Title)
	c.Links = record.CIAChangeLinks{Incident: ptr(in.ID)}
	return c
}
