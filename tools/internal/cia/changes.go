package cia

import (
	"sort"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// MaxChanges is how many change events the view keeps.
const MaxChanges = 500

// Snapshot is a declared incidents snapshot with the slot that wrote it.
type Snapshot struct {
	Slot    time.Time
	Content *record.CIAIncidents
}

// ChangeInput is what the changes view is derived from.
type ChangeInput struct {
	Runs      []*record.CIARun // the run records, oldest first
	Events    []record.CIAIncidentEvent
	Snapshots []Snapshot // oldest first
	// Complete says the files are the whole history. Without it they are a
	// slice: the oldest record sets the state, and only the events after its
	// fifth recorded slot are derived.
	Complete bool
}

// Changes derives data/v1/cia/changes.json (INCIDENTS-CONTRACT §8): every
// change event, newest first by at, ties by id, at most MaxChanges.
func Changes(in ChangeInput) []record.CIAChange {
	var all []record.CIAChange
	all = append(all, levelChanges(in.Runs)...)
	all = append(all, releaseAndFindingChanges(in.Runs)...)
	all = append(all, recordChanges(in.Runs)...)
	all = append(all, autoIncidentChanges(in.Events)...)
	all = append(all, declaredIncidentChanges(in.Snapshots)...)

	var out []record.CIAChange
	cutoff := ""
	if !in.Complete {
		cutoff = "9999" // fewer than five records: nothing to compare
		if len(in.Runs) >= 5 {
			cutoff = in.Runs[4].Slot
		}
	}
	for _, c := range all {
		if cutoff == "" || c.At > cutoff {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].At != out[j].At {
			return out[i].At > out[j].At
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > MaxChanges {
		out = out[:MaxChanges]
	}
	if out == nil {
		out = []record.CIAChange{}
	}
	return out
}

// Stamp is a time as the ids of change events write it: YYYYMMDDHHMM.
func Stamp(t time.Time) string { return t.UTC().Format("200601021504") }

func ptr[T any](v T) *T { return &v }

// event starts a change event at a slot, about a run record.
func event(id string, at, since time.Time, kind string) record.CIAChange {
	return record.CIAChange{ID: id, At: record.FormatTime(at), Since: record.FormatTime(since), Kind: kind,
		Services: []string{}, Categories: []string{},
		Links: record.CIAChangeLinks{Record: ptr(record.CIARunPath(at))}}
}
