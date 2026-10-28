package main

import (
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// ciaSim plays the auditor's CIA side: one run record per slot, the incident
// snapshots, the archived releases, and everything the views are derived from.
type ciaSim struct {
	w        *writer
	releases map[string]*release
	snaps    []*snapshot

	slots   map[time.Time]*cia.Slot // every run, synthetic history included
	finish  map[time.Time]time.Time // when each run finished
	history []cia.Slot              // the same, oldest first
	real    []*record.CIARun        // the run records written, oldest first
	prev    *record.Link            // the previous run record written
	last    *record.CIARun
	lastLnk record.Link
	runs    int

	signers map[string]note.Signer // the witnesses' keys as signed-note signers, by witness
	mem     v2Memory
}

// vantage is where the example probes run; the control probe is a request to a
// host that has nothing to do with diagnos.
const (
	vantage     = "scaleway:fr-par"
	controlHost = "connectivity.example"
)

// vantageSlot is the one run in the examples in which the auditor's own network
// failed: the control probe and every service probe failed, so nothing was
// measured. It is not an outage of any service.
var vantageSlot = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

// snapshotAt is the snapshot in force in the slot: the newest written by then.
func (c *ciaSim) snapshotAt(slot time.Time) *snapshot {
	var in *snapshot
	for _, s := range c.snaps {
		if !s.slot.After(slot) {
			in = s
		}
	}
	return in
}

// buildRun measures every service in the slot as the scenario says.
func (c *ciaSim) buildRun(slot, started, finished time.Time, logs map[string]logOutcome) *record.CIARun {
	snap := c.snapshotAt(slot)
	down := slot.Equal(vantageSlot)
	r := &record.CIARun{
		Schema: "cia-run/v1", Slot: record.FormatTime(slot), StartedAt: record.FormatTime(started),
		FinishedAt: record.FormatTime(finished), Vantage: vantage, Services: map[string]record.CIAService{},
		Control:   controlProbe("control", slot, down),
		Incidents: incidentsRead(slot, started, snap, down),
	}
	for _, id := range serviceIDs {
		p := probeAt(id, slot)
		if down {
			p = probe{release: "vantage"}
		}
		svc := record.CIAService{URL: serviceURL(id)}
		var health record.CIACheck
		if down {
			health = vantageHealthz(id, slot)
		} else {
			health = healthzCheck(id, slot, p.healthz)
		}
		avail := []record.CIACheck{health}
		integrity := []record.CIACheck{c.releaseCheck(id, slot, started, p.release)}
		if id == "status" {
			for _, log := range auditLogs {
				avail = append(avail, checkpointCheck(log, down))
				integrity = append(integrity, logCheck(log, logs[log]))
			}
		}
		svc.Availability, svc.Integrity = dimension(avail...), dimension(integrity...)
		svc.Confidentiality = dimension(incidentsCheck(id, slot, snap))
		r.Services[id] = svc
	}
	return r
}

// controlProbe is the control probe of a witness: a request to a host that has
// nothing to do with diagnos. When the witness's own network is down it fails.
func controlProbe(label string, slot time.Time, down bool) *record.CIAControl {
	c := &record.CIAControl{Host: controlHost, OK: !down, HTTPStatus: ptr(204), LatencyMs: ptr(22 + jitter(label, slot, 20))}
	if down {
		c.HTTPStatus, c.LatencyMs = nil, nil
	}
	return c
}

// incidentsRead says where the run read the declared incidents from. When the
// auditor's own network failed GitHub was out of reach too: the run used its
// last good copy.
func incidentsRead(slot, started time.Time, snap *snapshot, offline bool) record.CIARunIncidents {
	in := record.CIARunIncidents{Source: "github", Commit: ptr(fakeHex("develop " + slot.Format(record.DayLayout))),
		ReadAt: ptr(record.FormatTime(started.Add(time.Second)))}
	if offline {
		in.Source, in.ReadAt = "cache", ptr(record.FormatTime(readTime(slot.Add(-record.SlotLength))))
		in.Commit = ptr(fakeHex("develop " + slot.Add(-record.SlotLength).Format(record.DayLayout)))
	}
	if snap != nil {
		in.Snapshot = &record.Link{Record: snap.path, SHA256: snap.sha}
	}
	return in
}

// record writes the run record, chains it to the previous one and returns the
// link the hourly timestamp pins. A cia-run/v2 record is written as itself; the
// run it projects is what the views are derived from.
func (c *ciaSim) record(r *record.CIARun, slot time.Time) (record.Link, error) {
	r.Prev = c.prev
	var file any = r
	if r.V2 != nil {
		r.V2.Prev = c.prev
		file = r.V2
	}
	path := record.CIARunPath(slot)
	data, err := c.w.json(path, file)
	if err != nil {
		return record.Link{}, err
	}
	link := record.Link{Record: path, SHA256: sum(data)}
	c.prev, c.last, c.lastLnk = &link, r, link
	c.runs++
	c.real = append(c.real, r)
	if err := c.remember(r); err != nil {
		return link, err
	}
	for _, s := range c.snaps {
		if s.slot.Equal(slot) {
			err = s.write(c.w)
		}
	}
	return link, err
}
