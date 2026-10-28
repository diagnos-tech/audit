package cia

import (
	"sort"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// LatestInput is what the latest view is derived from.
type LatestInput struct {
	Run      *record.CIARun
	Path     string    // the run record's path
	FirstRun time.Time // the first run ever recorded
	Colour   Colourer
	// Since gives the start of the current level of a service's dimension.
	Since func(service, dimension string) time.Time
	// SnapshotPath is the declared snapshot in force, nil if none.
	SnapshotPath *string
	// SinceRegion and SinceWitness give the start of the current level of a
	// witness's probe of a service, and of the current status of a witness.
	// They are used for a cia-run/v2 record.
	SinceRegion  func(service, witness string) time.Time
	SinceWitness func(witness string) time.Time
}

// BuildLatest derives cia/latest.json from the latest run (INCIDENTS-CONTRACT
// §4): the level and code of each dimension are those of the day file at that
// slot, and its incidents are the ones that affect it, newest start first.
func BuildLatest(in LatestInput) *record.CIALatest {
	r := in.Run
	t, _ := record.ParseTime(r.Slot)
	out := &record.CIALatest{
		Schema: "cia-latest/v1", UpdatedAt: r.FinishedAt, Slot: r.Slot, Record: in.Path,
		FirstRun: record.FormatTime(in.FirstRun), Services: map[string]record.CIALatestService{},
		Incidents: record.CIALatestIncidents{Open: in.Colour.Incidents.OpenIDs(), Snapshot: in.SnapshotPath},
	}
	slot, _ := FromRun(r)
	var levels [3][]string
	for id, svc := range r.Services {
		var cells [3]Cell
		var ids [3][]string
		for d, name := range record.Dimensions {
			m := Result{Level: svc.Dimension(name).Level, Code: FirstCode(svc.Dimension(name))}
			cells[d] = in.Colour.Cell(id, d, t, m)
			ids[d] = affectingNewestFirst(in.Colour.Incidents.Affecting(id, name, t))
			levels[d] = append(levels[d], cells[d].Level)
		}
		since := func(dim string) string { return record.FormatTime(in.Since(id, dim)) }
		l := record.CIALatestService{URL: svc.URL}
		l.Availability = record.CIALatestAvailability{Level: cells[0].Level, Code: cells[0].Code, Since: since("availability"), Incidents: ids[0]}
		l.Integrity = record.CIALatestIntegrity{Level: cells[1].Level, Code: cells[1].Code, Since: since("integrity"), Incidents: ids[1]}
		l.Confidentiality = record.CIALatestConfidentiality{Level: cells[2].Level, Code: cells[2].Code, Since: since("confidentiality"), Incidents: ids[2]}
		for _, ch := range svc.Availability.Checks {
			if ch.Healthz != nil {
				l.Availability.LatencyMs = ch.Healthz.LatencyMs
			}
		}
		for _, ch := range svc.Integrity.Checks {
			if rel := ch.Release; rel != nil {
				l.Integrity.Version, l.Integrity.Commit, l.Integrity.Digest, l.Integrity.Verdict =
					rel.Version, rel.Commit, rel.Digest, rel.Verdict
			}
		}
		if r.V2 != nil {
			l.Availability.Regions = latestRegions(slot, id, func(w string) string { return record.FormatTime(in.SinceRegion(id, w)) })
		}
		out.Services[id] = l
	}
	if r.V2 != nil {
		out.Witnesses = latestWitnesses(slot, func(w string) string { return record.FormatTime(in.SinceWitness(w)) })
	}
	out.Headline = record.CIAHeadline{Availability: Worst(levels[0]...), Integrity: Worst(levels[1]...),
		Confidentiality: Worst(levels[2]...)}
	return out
}

func affectingNewestFirst(list []Incident) []string {
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
