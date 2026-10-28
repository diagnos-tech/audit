package check

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/incidents"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// eventSet is the automatic incidents found in the event facts.
type eventSet struct {
	all  []record.CIAIncidentEvent
	byID map[string][]record.CIAIncidentEvent // ordered by seq
}

// eventReports reads and checks every event fact (INCIDENTS-CONTRACT §5,
// checks 1 to 4 and 5). Checks that need the run records skip what a slice of the
// history does not hold.
func eventReports(rd *ciaReader, paths []string, f *ciaFacts) ([]*Report, *eventSet) {
	set := &eventSet{byID: map[string][]record.CIAIncidentEvent{}}
	reports := make([]*Report, len(paths))
	events := make([]*record.CIAIncidentEvent, len(paths))
	for i, p := range paths {
		reports[i] = &Report{Subject: p}
		events[i] = readEvent(rd, p, reports[i])
		if events[i] != nil {
			set.all = append(set.all, *events[i])
		}
	}
	set.byID = cia.FoldEvents(set.all)
	for i, e := range events {
		if e == nil {
			continue
		}
		checkEventSequence(e, set.byID[e.ID], reports[i])
		checkEventAgainstRuns(f, e, reports[i])
	}
	return reports, set
}

func readEvent(rd *ciaReader, path string, r *Report) *record.CIAIncidentEvent {
	data, err := rd.read(path)
	if err != nil {
		r.fail("read", "%v", err)
		return nil
	}
	var e record.CIAIncidentEvent
	if err := record.Decode(data, "cia-incident-event/v1", &e); err != nil {
		r.fail("format", "%v", err)
		return nil
	}
	at, err := record.ParseTime(e.At)
	started, err2 := record.ParseTime(e.StartedAt)
	switch {
	case err != nil || err2 != nil || !at.Equal(record.SlotOf(at)) || !started.Equal(record.SlotOf(started)):
		r.fail("format", "at and startedAt must be slots")
	case !incidents.IsAutoID(e.ID):
		r.fail("name", "%q is not the id of an automatic incident", e.ID)
	case record.CIAIncidentEventPath(e.ID, e.Seq, at) != path:
		r.fail("name", "the event %d of %s, written at %s, belongs at %s", e.Seq, e.ID, e.At, record.CIAIncidentEventPath(e.ID, e.Seq, at))
	case e.Source != "auditor":
		r.fail("format", "source must be auditor")
	case e.Run != record.CIARunPath(at):
		r.fail("run", "the run of slot %s is %s, not %s", e.At, record.CIARunPath(at), e.Run)
	case idProblem(&e, started) != "":
		r.fail("id", "%s", idProblem(&e, started))
	case timeProblem(&e, at, started) != "":
		r.fail("times", "%s", timeProblem(&e, at, started))
	default:
		r.pass("event", "%s %d: %s at %s", e.ID, e.Seq, e.Type, e.At)
		return &e
	}
	return nil
}

// idProblem checks that the id agrees with the fields it is made of: the day
// and time of startedAt, the service and the category.
func idProblem(e *record.CIAIncidentEvent, started time.Time) string {
	letter := map[string]string{"A": "a", "I": "i"}[e.Categories[0]]
	want := started.Format("2006-01-02") + "-auto-" + e.Services[0] + "-" + letter + "-" + started.Format("1504")
	if e.ID != want {
		return fmt.Sprintf("the id of an incident of %s, category %s, started %s is %s, not %s", e.Services[0], e.Categories[0], e.StartedAt, want, e.ID)
	}
	return ""
}

func timeProblem(e *record.CIAIncidentEvent, at, started time.Time) string {
	switch {
	case started.After(at):
		return "startedAt is after at"
	case e.Type != "resolved" && e.ResolvedAt != nil:
		return "resolvedAt is only set by the resolved event"
	case e.Type == "resolved" && e.ResolvedAt == nil:
		return "the resolved event has no resolvedAt"
	case e.ResolvedAt != nil:
		resolved, err := record.ParseTime(*e.ResolvedAt)
		if err != nil || !resolved.Equal(record.SlotOf(resolved)) || resolved.Before(started) || resolved.After(at) {
			return "resolvedAt must be a slot between startedAt and at"
		}
	}
	return ""
}

// checkEventSequence: seq counts 1, 2, 3 ... without gaps; the first event
// opens, only the last may resolve; at only grows; categories, services and
// startedAt never change.
func checkEventSequence(e *record.CIAIncidentEvent, same []record.CIAIncidentEvent, r *Report) {
	first, last := same[0], same[len(same)-1]
	switch {
	case e.Seq > len(same) || same[e.Seq-1].Seq != e.Seq:
		r.fail("sequence", "the events of %s are not numbered 1, 2, 3 without gaps", e.ID)
	case (e.Seq == 1) != (e.Type == "opened"):
		r.fail("sequence", "event %d is %s: only the first opens", e.Seq, e.Type)
	case e.Type == "resolved" && e.Seq != last.Seq:
		r.fail("sequence", "the incident was resolved by event %d but has event %d after it", e.Seq, last.Seq)
	case e.Seq > 1 && e.At <= same[e.Seq-2].At:
		r.fail("sequence", "event %d is at %s, not after event %d (%s)", e.Seq, e.At, e.Seq-1, same[e.Seq-2].At)
	case !equalStrings(e.Categories, first.Categories) || !equalStrings(e.Services, first.Services) || e.StartedAt != first.StartedAt:
		r.fail("constant", "categories, services and startedAt must not change between the events of an incident")
	default:
		r.pass("sequence", "event %d of %d", e.Seq, len(same))
	}
}

func equalStrings(a, b []string) bool { return strings.Join(a, "\x00") == strings.Join(b, "\x00") }

// checkEventAgainstRuns is check 5: the measurements agree with the event. It
// says nothing about a slot whose run record is not among the files.
func checkEventAgainstRuns(f *ciaFacts, e *record.CIAIncidentEvent, r *Report) {
	service, category := e.Services[0], e.Categories[0]
	dim := map[string]string{"A": "availability", "I": "integrity"}[category]
	measured := func(t time.Time) (level string, recorded bool) {
		run, ok := f.byTime[t]
		if !ok {
			return "", false
		}
		svc, ok := run.Services[service]
		return svc.Dimension(dim).Level, ok
	}
	started, at := mustTime(e.StartedAt), mustTime(e.At)
	switch e.Type {
	case "opened":
		if problem := openProblem(measured, category, started, at); problem != "" {
			r.fail("measurements", "%s", problem)
		}
	case "resolved":
		resolved := mustTime(*e.ResolvedAt)
		for _, t := range []time.Time{resolved, nextRecorded(f, resolved)} {
			if level, ok := measured(t); ok && level == record.LevelFail {
				r.fail("measurements", "%s is %s at %s, but the incident was resolved from %s", dim, level, record.FormatTime(t), *e.ResolvedAt)
			}
		}
	}
}

// openProblem: an availability incident opens at the third failing slot, at
// least ten minutes after its start, so every slot measured in between failed;
// an integrity incident opens at once, on a failing slot.
func openProblem(measured func(time.Time) (string, bool), category string, started, at time.Time) string {
	first, ok1 := measured(started)
	last, ok2 := measured(at)
	if !ok1 || !ok2 {
		return "" // part of the history is not here
	}
	if first != record.LevelFail || last != record.LevelFail {
		return fmt.Sprintf("the incident starts at %s and opens at %s, but the measured levels there are %s and %s, not fail",
			record.FormatTime(started), record.FormatTime(at), first, last)
	}
	if category == "I" {
		return ""
	}
	if at.Sub(started) < 10*time.Minute {
		return "an availability incident opens after three failed slots, at least 10 minutes after it started"
	}
	for t := started; t.Before(at); t = t.Add(record.SlotLength) {
		if level, ok := measured(t); ok && level != record.LevelFail && level != record.LevelNone {
			return fmt.Sprintf("availability is %s at %s, inside the incident's first failed slots", level, record.FormatTime(t))
		}
	}
	return ""
}

// nextRecorded is the first recorded slot after t (t itself if there is none).
func nextRecorded(f *ciaFacts, t time.Time) time.Time {
	i := sort.Search(len(f.chain), func(i int) bool { return f.chain[i].Time.After(t) })
	if i == len(f.chain) {
		return t
	}
	return f.chain[i].Time
}
