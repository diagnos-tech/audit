package check

import (
	"sort"
	"strings"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// CIAOptions tunes the CIA checks.
type CIAOptions struct {
	// Complete says the files are the whole history: the oldest run record
	// is the first run, and no day is missing a record. Without it they may be a
	// slice, as the example data is.
	Complete bool
	Release  ReleaseOptions
	// Keys are the keys to trust; the repository's keys/ when nil. Witness
	// measurements are verified with them.
	Keys *Keyring
}

// ciaTree lists the CIA files of a repository, sorted.
type ciaTree struct {
	runs, snapshots, events, days, releaseDirs   []string
	summary, latest, view, changes, recent, sync bool
}

func (t *ciaTree) empty() bool {
	return len(t.runs)+len(t.snapshots)+len(t.events)+len(t.days)+len(t.releaseDirs) == 0 &&
		!t.summary && !t.latest && !t.view && !t.changes && !t.recent && !t.sync
}

// CIA checks the CIA record: each run record on its own, the chain between
// them, the incident snapshots and events and the releases, and then the views
// (day files, summary, latest, incident list, changes) against what the facts
// derive.
func CIA(src record.Source, t *ciaTree, opts CIAOptions) []*Report {
	rd := newCIAReader(src)
	if opts.Keys == nil {
		opts.Keys = NewKeyring(src, "keys/")
	}
	var reports []*Report
	recs := make([]*record.CIARun, len(t.runs))
	datas := make([][]byte, len(t.runs))
	runReports := make([]*Report, len(t.runs))
	for i, p := range t.runs {
		recs[i], datas[i], runReports[i] = ciaRun(src, opts.Keys, rd, p)
		if recs[i] != nil {
			checkSnapshotLink(rd, t.snapshots, recs[i], opts.Complete, runReports[i])
			if recs[i].V2 == nil {
				checkRunLinks(rd, recs[i], runReports[i])
			}
		}
	}
	checkChain(rd, t.runs, datas, recs, runReports, opts.Complete)
	reports = append(reports, runReports...)

	f := newFacts(t, recs)
	var newestReport *Report
	for _, p := range t.snapshots {
		r, content, _ := snapshotReport(rd, p)
		reports = append(reports, r)
		newestReport = r
		if content != nil {
			f.declared = append(f.declared, cia.Snapshot{Slot: snapshotSlot(p), Content: content})
			f.newest = content
		}
	}
	eventReports, set := eventReports(rd, t.events, f)
	reports = append(reports, eventReports...)
	f.events = set
	f.colour = colourer(f.newest, set)
	for _, problem := range relatesReportProblems(f.newest, set) {
		newestReport.fail("relates", "%s", problem)
	}
	if len(f.runs) > 0 {
		reports = append(reports, coverageReport(f, set, opts.Complete))
	}
	for _, d := range t.releaseDirs {
		reports = append(reports, Release(src, d, opts.Release))
	}
	return append(reports, ciaViews(rd, t, f, opts)...)
}

func newFacts(t *ciaTree, recs []*record.CIARun) *ciaFacts {
	f := &ciaFacts{slots: map[time.Time]*cia.Slot{}, byTime: map[time.Time]*record.CIARun{}, snapshots: t.snapshots,
		events: &eventSet{byID: map[string][]record.CIAIncidentEvent{}}}
	for i, rec := range recs {
		if rec == nil {
			continue
		}
		slot, err := cia.FromRun(rec)
		if err != nil {
			continue
		}
		f.paths, f.runs = append(f.paths, t.runs[i]), append(f.runs, rec)
		f.slots[slot.Time], f.byTime[slot.Time] = &slot, rec
		f.chain = append(f.chain, slot)
	}
	return f
}

// colourer holds the state of the incidents that colours the views: the
// declared incidents of the newest snapshot and the automatic ones in the state
// of their latest event.
func colourer(newest *record.CIAIncidents, set *eventSet) cia.Colourer {
	var incidents cia.Incidents
	if newest != nil {
		incidents, _ = cia.FromSnapshot(newest)
	}
	auto, _ := cia.FromEvents(set.byID)
	return cia.Colourer{Incidents: append(incidents, auto...), HaveSnapshot: newest != nil}
}

func snapshotSlot(path string) time.Time {
	t, _ := time.Parse("2006/01/02/1504Z.json", strings.TrimPrefix(path, "data/v1/cia/incidents/"))
	return t
}

func ciaViews(rd *ciaReader, t *ciaTree, f *ciaFacts, opts CIAOptions) []*Report {
	var reports []*Report
	if len(f.runs) == 0 {
		for _, p := range viewPaths(t) {
			r := &Report{Subject: p}
			r.fail("derived", "there is no run record to derive it from")
			reports = append(reports, r)
		}
		return reports
	}
	days := map[string]*record.CIADay{}
	listed := map[string]bool{}
	for _, p := range t.days {
		r, day := dayReport(rd, f, p, opts.Complete)
		reports = append(reports, r)
		if day != nil {
			days[day.Day] = day
			listed[p] = true
		}
	}
	for _, d := range recordedDays(f) {
		if !listed[record.CIADayPath(d)] {
			reports = append(reports, missingDay(d))
		}
	}
	first := slotTime(f.runs[0])
	if t.summary {
		r := summaryReport(rd, f, days, opts.Complete)
		reports = append(reports, r)
		if got, err := firstRunOf(rd); err == nil {
			first = got
		}
	} else {
		reports = append(reports, missingView(record.CIASummaryPath))
	}
	reports = append(reports, viewOrMissing(t.latest, record.CIALatestPath, func() *Report { return latestReport(rd, f, first, opts.Complete) }),
		viewOrMissing(t.view, record.CIAIncidentsViewPath, func() *Report { return incidentListReport(rd, f) }),
		viewOrMissing(t.changes, record.CIAChangesPath, func() *Report { return changesReport(rd, f, opts.Complete) }),
		viewOrMissing(t.recent, record.CIARecentPath, func() *Report { return recentReport(rd, f, opts.Complete) }))
	if t.sync {
		reports = append(reports, syncReport(rd, f))
	}
	return reports
}

func viewOrMissing(exists bool, path string, check func() *Report) *Report {
	if !exists {
		return missingView(path)
	}
	return check()
}

func missingView(path string) *Report {
	r := &Report{Subject: path}
	r.fail("exists", "there are run records but this view is missing")
	return r
}

func viewPaths(t *ciaTree) []string {
	paths := append([]string(nil), t.days...)
	for _, v := range []struct {
		exists bool
		path   string
	}{{t.summary, record.CIASummaryPath}, {t.latest, record.CIALatestPath}, {t.view, record.CIAIncidentsViewPath}, {t.changes, record.CIAChangesPath}, {t.recent, record.CIARecentPath}} {
		if v.exists {
			paths = append(paths, v.path)
		}
	}
	sort.Strings(paths)
	return paths
}

// recordedDays lists the UTC days that have at least one run record.
func recordedDays(f *ciaFacts) []time.Time {
	seen := map[time.Time]bool{}
	var days []time.Time
	for _, s := range f.chain {
		if d := s.Time.Truncate(24 * time.Hour); !seen[d] {
			seen[d] = true
			days = append(days, d)
		}
	}
	return days
}

func firstRunOf(rd *ciaReader) (time.Time, error) {
	data, err := rd.read(record.CIASummaryPath)
	if err != nil {
		return time.Time{}, err
	}
	var s record.CIASummary
	if err := record.Decode(data, "cia-summary/v1", &s); err != nil {
		return time.Time{}, err
	}
	return record.ParseTime(s.FirstRun)
}

// syncReport: the mirror cursor is written together with the latest run.
func syncReport(rd *ciaReader, f *ciaFacts) *Report {
	r := &Report{Subject: record.SyncPath}
	var s record.Sync
	data, err := rd.read(record.SyncPath)
	if err == nil {
		err = record.Decode(data, "sync/v1", &s)
	}
	if err != nil {
		r.fail("read", "%v", err)
		return r
	}
	at, err := record.ParseTime(s.SyncedAt)
	finished := mustTime(f.last().FinishedAt)
	if err != nil || at.Before(finished) {
		r.fail("cursor", "synced at %s, before the latest run finished (%s)", s.SyncedAt, f.last().FinishedAt)
		return r
	}
	r.pass("cursor", "journal entry %d, synced %s", s.Seq, s.SyncedAt)
	return r
}
