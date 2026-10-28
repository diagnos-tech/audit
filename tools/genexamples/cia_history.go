package main

import (
	"fmt"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// firstRun is where the example record begins: the 90-day window is full, and the witness window of the examples is the end of a longer history.
var firstRun = time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)

func newCIASim(w *writer, incidentsDir string) (*ciaSim, error) {
	snaps, err := loadSnapshots(incidentsDir)
	if err != nil {
		return nil, err
	}
	c := &ciaSim{w: w, releases: map[string]*release{}, snaps: snaps,
		slots: map[time.Time]*cia.Slot{}, finish: map[time.Time]time.Time{}}
	rels, err := exampleReleases()
	if err != nil {
		return nil, err
	}
	for _, r := range rels {
		c.releases[r.service] = r
		if err := r.writeTo(w); err != nil {
			return nil, err
		}
	}
	signers := record.Signers{Schema: "signers/v1", Services: exampleSigners}
	_, err = w.json(record.SignersPath, signers)
	return c, err
}

// synthesize plays the auditor over the months before the witness records of
// the examples begin. Nothing is written for them: they exist so the day files
// and the 90-day summary have the history a real record would have, and so
// that `since` reaches back to the first run. The gaps of auditorGaps apply.
func (c *ciaSim) synthesize() error {
	clean := map[string]logOutcome{"audit": {status: "unchanged"}, "signs": {status: "unchanged"}}
	var last time.Time
	for t := firstRun; t.Before(start); t = t.Add(record.SlotLength) {
		if inGap(t) {
			continue
		}
		if err := c.remember(c.buildRun(t, t.Add(time.Second), t.Add(9*time.Second), clean)); err != nil {
			return err
		}
		last = t
	}
	// The first real record links the last synthetic one, which the examples
	// do not contain (they are a slice of a longer history).
	path := record.CIARunPath(last)
	c.prev = &record.Link{Record: path, SHA256: sum([]byte("example record that is not part of the examples: " + path))}
	return nil
}

// remember keeps what the views are derived from.
func (c *ciaSim) remember(r *record.CIARun) error {
	s, err := cia.FromRun(r)
	if err != nil {
		return err
	}
	finished, err := record.ParseTime(r.FinishedAt)
	if err != nil {
		return err
	}
	c.slots[s.Time], c.finish[s.Time] = &s, finished
	c.history = append(c.history, s)
	return nil
}

func journalDigest(seq int) string { return sum([]byte(fmt.Sprintf("example journal entry %d", seq))) }
