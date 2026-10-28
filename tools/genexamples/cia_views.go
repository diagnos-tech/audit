package main

import (
	"slices"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// recentChanges is how many change events changes-recent.json keeps.
const recentChanges = 30

// writeViews writes what the sync step derives from the facts: the automatic
// incidents (facts, from the auditor's policy), then the day files, the 90-day
// summary, the latest headline, the incident list, the change events and the
// cursor. The projections are the ones `verify cia` recomputes them with.
func (c *ciaSim) writeViews() error {
	final := c.snaps[len(c.snaps)-1]
	events := autoEvents(c.history)
	for _, e := range events {
		if _, err := c.w.json(record.CIAIncidentEventPath(e.ID, e.Seq, mustTime(e.At)), e); err != nil {
			return err
		}
	}
	byID := cia.FoldEvents(events)
	auto, err := cia.FromEvents(byID)
	if err != nil {
		return err
	}
	colour := cia.Colourer{Incidents: append(append(cia.Incidents{}, final.incidents...), auto...), HaveSnapshot: true}

	last := c.last
	lastSlot := mustTime(last.Slot)
	to := lastSlot.Truncate(24 * time.Hour)
	days := map[string]*record.CIADay{}
	for d := to.AddDate(0, 0, -(cia.WindowDays - 1)); !d.After(to); d = d.AddDate(0, 0, 1) {
		in := cia.DayInput{Day: d, Colour: colour}
		for i := range in.Slots {
			in.Slots[i] = c.slots[d.Add(time.Duration(i)*record.SlotLength)]
		}
		if !slices.ContainsFunc(in.Slots[:], func(s *cia.Slot) bool { return s != nil }) {
			continue // a day without a run has no day file; the summary counts it as no data
		}
		day := cia.BuildDay(in)
		day.UpdatedAt = record.FormatTime(c.updatedAt(d, colour, events))
		if _, err := c.w.compact(record.CIADayPath(d), day); err != nil {
			return err
		}
		days[day.Day] = day
	}
	if _, err := c.w.compact(record.CIASummaryPath, cia.BuildSummary(days, firstRun, to, last.FinishedAt)); err != nil {
		return err
	}
	latest := cia.BuildLatest(cia.LatestInput{
		Run: last, Path: c.lastLnk.Record, FirstRun: firstRun, Colour: colour, SnapshotPath: &final.path,
		Since: func(service, dimension string) time.Time {
			since, _ := cia.Since(c.history, colour, service, dimension)
			return since
		},
		SinceRegion: func(service, witness string) time.Time {
			since, _ := cia.RegionSince(c.history, service, witness)
			return since
		},
		SinceWitness: func(witness string) time.Time {
			since, _ := cia.WitnessSince(c.history, witness)
			return since
		},
	})
	if _, err := c.w.compact(record.CIALatestPath, latest); err != nil {
		return err
	}
	if _, err := c.w.compact(record.CIAIncidentsViewPath, cia.BuildIncidentList(final.path, final.content, byID)); err != nil {
		return err
	}
	changes := c.changes(events, false)
	if _, err := c.w.compact(record.CIAChangesPath, record.CIAChanges{Schema: "cia-changes/v1", Events: changes}); err != nil {
		return err
	}
	if _, err := c.w.compact(record.CIARecentPath, record.CIAChanges{Schema: "cia-changes-recent/v1", Events: changes[:min(recentChanges, len(changes))]}); err != nil {
		return err
	}
	finished := mustTime(last.FinishedAt)
	seq := len(c.history)
	_, err = c.w.json(record.SyncPath, record.Sync{Schema: "sync/v1", Seq: seq, Journal: journalDigest(seq),
		SyncedAt: record.FormatTime(finished.Add(3 * time.Second))})
	return err
}

// changes derives the change events of the run records written (the window of
// the examples, not the scripted history before it).
func (c *ciaSim) changes(events []record.CIAIncidentEvent, complete bool) []record.CIAChange {
	var snaps []cia.Snapshot
	for _, s := range c.snaps {
		snaps = append(snaps, cia.Snapshot{Slot: s.slot, Content: s.content})
	}
	return cia.Changes(cia.ChangeInput{Runs: c.real, Events: events, Snapshots: snaps, Complete: complete})
}

// updatedAt is when the sync last rewrote the day file: after the last run of
// the day, or when an incident that overlaps the day changed state.
func (c *ciaSim) updatedAt(day time.Time, colour cia.Colourer, events []record.CIAIncidentEvent) time.Time {
	updated := day.Add(24*time.Hour - time.Second)
	for i := 0; i < cia.SlotsPerDay; i++ {
		if f, ok := c.finish[day.Add(time.Duration(i)*record.SlotLength)]; ok {
			updated = f
		}
	}
	states := map[string]cia.Incident{}
	for _, in := range colour.Incidents {
		states[in.ID] = in
	}
	for _, ch := range c.changes(events, true) {
		in, ok := states[incidentOfChange(ch)]
		if !ok || !in.Start.Before(day.Add(24*time.Hour)) || (in.End != nil && !in.End.After(day)) {
			continue
		}
		if f, ok := c.finish[mustTime(ch.At)]; ok && f.After(updated) {
			updated = f
		}
	}
	return updated
}

func incidentOfChange(ch record.CIAChange) string {
	if ch.Links.Incident != nil {
		return *ch.Links.Incident
	}
	return ""
}

func mustTime(s string) time.Time {
	t, err := record.ParseTime(s)
	if err != nil {
		panic("genexamples: " + err.Error())
	}
	return t
}
