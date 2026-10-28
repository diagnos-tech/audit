package check

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// changesReport derives data/v1/cia/changes.json again from the run records
// and the incident facts and compares it event by event, so that a change that
// was hidden, invented or reworded is named. Without complete, the events up to
// the fifth recorded slot are not compared: the oldest record only sets the
// state.
func changesReport(rd *ciaReader, f *ciaFacts, complete bool) *Report {
	r := &Report{Subject: record.CIAChangesPath}
	got, ok := readChanges(rd, record.CIAChangesPath, "cia-changes/v1", r)
	if !ok {
		return r
	}
	want, cutoff := derivedChanges(f, complete)
	if problem := changesProblem(want, afterCutoff(got.Events, cutoff, complete)); problem != "" {
		r.fail("derived", "%s", problem)
		return r
	}
	r.pass("derived", "%d change events, derived again from the run records and the incident facts", len(got.Events))
	return r
}

// recentReport: changes-recent.json is the first 30 events of the derived list.
func recentReport(rd *ciaReader, f *ciaFacts, complete bool) *Report {
	r := &Report{Subject: record.CIARecentPath}
	got, ok := readChanges(rd, record.CIARecentPath, "cia-changes-recent/v1", r)
	if !ok {
		return r
	}
	want, cutoff := derivedChanges(f, complete)
	shown := afterCutoff(got.Events, cutoff, complete)
	head := want[:min(recentLimit, len(want))]
	if len(shown) < len(head) && len(got.Events) == len(shown) { // nothing was left out because of the slice
		r.fail("derived", "lists %d events, the head of the derived list has %d: event %s is missing", len(shown), len(head), head[len(shown)].ID)
		return r
	}
	if problem := changesProblem(head[:min(len(head), len(shown))], shown); problem != "" {
		r.fail("derived", "%s", problem)
		return r
	}
	r.pass("derived", "the first %d of the %d derived change events", len(got.Events), len(want))
	return r
}

// recentLimit is how many events changes-recent.json holds.
const recentLimit = 30

func readChanges(rd *ciaReader, path, schema string, r *Report) (*record.CIAChanges, bool) {
	var got record.CIAChanges
	data, err := rd.read(path)
	if err == nil {
		err = record.Decode(data, schema, &got)
	}
	if err != nil {
		r.fail("read", "%v", err)
		return nil, false
	}
	return &got, true
}

// derivedChanges is the list the facts give. Without complete, the events up
// to the fifth recorded slot are left out, because the oldest record only sets
// the state; cutoff is that slot.
func derivedChanges(f *ciaFacts, complete bool) (want []record.CIAChange, cutoff string) {
	cutoff = "9999" // fewer than five records: nothing is compared
	if len(f.runs) >= 5 {
		cutoff = f.runs[4].Slot
	}
	return cia.Changes(cia.ChangeInput{Runs: f.runs, Events: f.events.all, Snapshots: f.declared, Complete: complete}), cutoff
}

func afterCutoff(events []record.CIAChange, cutoff string, complete bool) []record.CIAChange {
	var out []record.CIAChange
	for _, c := range events {
		if complete || c.At > cutoff {
			out = append(out, c)
		}
	}
	return out
}

// changesProblem names the first difference between the derived events and the
// events of the file, both newest first.
func changesProblem(want, got []record.CIAChange) string {
	wantByID := map[string]record.CIAChange{}
	for _, c := range want {
		wantByID[c.ID] = c
	}
	gotByID := map[string]bool{}
	for i, c := range got {
		gotByID[c.ID] = true
		w, ok := wantByID[c.ID]
		switch {
		case !ok:
			return fmt.Sprintf("event %s (%s at %s) is not derived from the records: a change that did not happen", c.ID, c.Kind, c.At)
		case !reflect.DeepEqual(w, c):
			return fmt.Sprintf("event %s differs from what the records give: file %s, derived %s", c.ID, changeText(c), changeText(w))
		case i > 0 && !before(got[i-1], c):
			return fmt.Sprintf("event %s is out of order: newest first by at, ties by id", c.ID)
		}
	}
	missing := make([]string, 0)
	for _, w := range want {
		if !gotByID[w.ID] {
			missing = append(missing, w.ID)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return fmt.Sprintf("event %s (%s) is missing: a change the records show is not listed", missing[0], wantByID[missing[0]].Kind)
	}
	return ""
}

func before(a, b record.CIAChange) bool { return a.At > b.At || a.At == b.At && a.ID < b.ID }

func changeText(c record.CIAChange) string { return fmt.Sprintf("%q at %s", c.Summary.EN, c.At) }
