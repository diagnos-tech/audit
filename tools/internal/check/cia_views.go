package check

import (
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// ciaFacts is what the views are derived from, gathered from the run records
// that were read.
type ciaFacts struct {
	paths     []string // run record paths, oldest first
	runs      []*record.CIARun
	slots     map[time.Time]*cia.Slot
	byTime    map[time.Time]*record.CIARun
	chain     []cia.Slot
	snapshots []string             // declared snapshot paths, oldest first
	declared  []cia.Snapshot       // the same, decoded
	newest    *record.CIAIncidents // the newest snapshot, nil if there is none
	events    *eventSet            // the automatic incidents
	colour    cia.Colourer         // the state of the incidents, which colours the views
}

func (f *ciaFacts) last() *record.CIARun { return f.runs[len(f.runs)-1] }

// summaryReport recomputes cia/summary.json from the day files and compares.
func summaryReport(rd *ciaReader, f *ciaFacts, days map[string]*record.CIADay, complete bool) *Report {
	r := &Report{Subject: record.CIASummaryPath}
	var got record.CIASummary
	data, err := rd.read(record.CIASummaryPath)
	if err == nil {
		err = record.Decode(data, "cia-summary/v1", &got)
	}
	if err != nil {
		r.fail("read", "%v", err)
		return r
	}
	first, err := record.ParseTime(got.FirstRun)
	oldest := slotTime(f.runs[0])
	switch {
	case err != nil:
		r.fail("firstRun", "%v", err)
		return r
	case complete && !first.Equal(oldest):
		r.fail("firstRun", "%s is not the slot of the oldest run record, %s", got.FirstRun, f.runs[0].Slot)
	case first.After(oldest):
		r.fail("firstRun", "%s is after the oldest run record, %s", got.FirstRun, f.runs[0].Slot)
	default:
		r.pass("firstRun", "%s", got.FirstRun)
	}
	for _, id := range sortedKeys(got.Services) {
		if len(got.Services[id].P95Ms) != cia.WindowDays {
			r.fail("derived", "%s has no p95Ms: the summary carries the daily 95th percentile latency of each service", id)
			return r
		}
	}
	to := slotTime(f.last()).Truncate(24 * time.Hour)
	want := cia.BuildSummary(days, first, to, f.last().FinishedAt)
	if diffs := diffEncoded(want, &got, func(*record.CIASummary) {}); len(diffs) > 0 {
		r.fail("derived", "differs from the day files: %s", diffs[0])
	} else {
		r.pass("derived", "%s to %s, recomputed from %d day files", got.From, got.To, len(days))
	}
	return r
}

// latestReport recomputes cia/latest.json from the latest run record.
func latestReport(rd *ciaReader, f *ciaFacts, first time.Time, complete bool) *Report {
	r := &Report{Subject: record.CIALatestPath}
	var got record.CIALatest
	data, err := rd.read(record.CIALatestPath)
	if err == nil {
		err = record.Decode(data, "cia-latest/v1", &got)
	}
	if err != nil {
		r.fail("read", "%v", err)
		return r
	}
	last := f.last()
	in := cia.LatestInput{Run: last, Path: f.paths[len(f.paths)-1], FirstRun: first, Colour: f.colour}
	if link := last.Incidents.Snapshot; link != nil {
		in.SnapshotPath = &link.Record
	}
	in.Since = func(service, dimension string) time.Time {
		since, reachedStart := cia.Since(f.chain, f.colour, service, dimension)
		if claimed, ok := claimedSince(&got, service, dimension); ok && reachedStart && !complete &&
			!claimed.Before(first) && !claimed.After(since) {
			return claimed // older runs, outside these files, may extend the sequence
		}
		return since
	}
	if diffs := diffEncoded(cia.BuildLatest(in), &got, func(*record.CIALatest) {}); len(diffs) > 0 {
		r.fail("derived", "differs from the latest run record: %s", diffs[0])
	} else {
		r.pass("derived", "headline %s/%s/%s from %s", got.Headline.Availability, got.Headline.Integrity, got.Headline.Confidentiality, got.Record)
	}
	return r
}

func claimedSince(l *record.CIALatest, service, dimension string) (time.Time, bool) {
	s, ok := l.Services[service]
	if !ok {
		return time.Time{}, false
	}
	var v string
	switch dimension {
	case "availability":
		v = s.Availability.Since
	case "integrity":
		v = s.Integrity.Since
	default:
		v = s.Confidentiality.Since
	}
	t, err := record.ParseTime(v)
	return t, err == nil
}

// incidentListReport recomputes data/v1/cia/incidents.json (the declared
// incidents of the newest snapshot and the automatic ones folded from their
// events) and compares.
func incidentListReport(rd *ciaReader, f *ciaFacts) *Report {
	r := &Report{Subject: record.CIAIncidentsViewPath}
	var got record.CIAIncidentList
	data, err := rd.read(record.CIAIncidentsViewPath)
	if err == nil {
		err = record.Decode(data, "cia-incident-list/v1", &got)
	}
	if err != nil {
		r.fail("read", "%v", err)
		return r
	}
	newestPath := ""
	if len(f.snapshots) > 0 {
		newestPath = f.snapshots[len(f.snapshots)-1]
	}
	want := cia.BuildIncidentList(newestPath, f.newest, f.events.byID)
	if diffs := diffEncoded(want, &got, func(*record.CIAIncidentList) {}); len(diffs) > 0 {
		r.fail("derived", "differs from the snapshot and the events: %s", diffs[0])
	} else {
		r.pass("derived", "%d incidents: %d declared, %d automatic", len(got.Incidents), len(want.Incidents)-len(f.events.byID), len(f.events.byID))
	}
	return r
}

// dayReport compares one day file with the one derived from the run records.
func dayReport(rd *ciaReader, f *ciaFacts, path string, complete bool) (*Report, *record.CIADay) {
	r := &Report{Subject: path}
	var got record.CIADay
	data, err := rd.read(path)
	if err == nil {
		err = record.Decode(data, "cia-day/v1", &got)
	}
	if err != nil {
		r.fail("read", "%v", err)
		return r, nil
	}
	day, err := dayStart(got.Day)
	if err != nil || record.CIADayPath(day) != path {
		r.fail("day", "the file of day %s belongs at %s", got.Day, record.CIADayPath(day))
		return r, &got
	}
	if problems := validateDay(&got); len(problems) > 0 {
		r.fail("structure", "%s", problems[0])
		return r, &got
	}
	in := cia.DayInput{Day: day, Colour: f.colour}
	var present [cia.SlotsPerDay]bool
	any := false
	for i := range in.Slots {
		if s, ok := f.slots[day.Add(time.Duration(i)*record.SlotLength)]; ok {
			in.Slots[i], present[i], any = s, true, true
		}
	}
	switch {
	case !any && complete:
		r.fail("derived", "no run record backs this day file")
	case !any:
		r.pass("derived", "no run records of this day in these files; only its structure was checked")
	default:
		if diffs := compareDay(cia.BuildDay(in), &got, present, complete); len(diffs) > 0 {
			r.fail("derived", "differs from the run records: %s", diffs[0])
		} else {
			r.pass("derived", "recomputed from the run records and the newest incidents snapshot")
		}
	}
	return r, &got
}

func missingDay(day time.Time) *Report {
	r := &Report{Subject: record.CIADayPath(day)}
	r.fail("exists", "there are run records of %s but no day file", day.Format(record.DayLayout))
	return r
}
