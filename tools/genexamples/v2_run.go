package main

import (
	"fmt"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// v2Memory is what the primary remembers of the second witness between runs.
type v2Memory struct {
	peerLast  string // the run record the secondary checked at its last run
	committed string // the digest of the secondary's last measurement the primary committed
}

// regionLabel is how the examples' error texts name a witness's region.
var regionLabel = map[string]string{record.WitnessEurope: "Europe", record.WitnessLatam: "Latin America"}

// buildRunV2 plays one run of the primary with two witnesses: each measures,
// signs what it measured, and the primary combines what the measuring ones
// saw. eu and la are what each did with the logs; la is nil when the secondary
// did nothing.
func (c *ciaSim) buildRunV2(slot, started, finished time.Time, eu, la map[string]logOutcome, plan v2Plan) (*record.CIARunV2, error) {
	snap := c.snapshotAt(slot)
	r := &record.CIARunV2{
		Schema: "cia-run/v2", Slot: record.FormatTime(slot), StartedAt: record.FormatTime(started), FinishedAt: record.FormatTime(finished),
		Incidents: incidentsRead(slot, started, snap, plan.europeDown),
		Witnesses: map[string]record.WitnessEntry{}, Services: map[string]record.CIAServiceV2{},
	}
	europe := c.measured(record.WitnessEurope, slot, started, plan, eu, nil)
	entry, err := c.signedEntry(record.WitnessEurope, slot, "none", europe)
	if err != nil {
		return nil, err
	}
	r.Witnesses[record.WitnessEurope] = entry
	if r.Witnesses[record.WitnessLatam], err = c.secondaryEntry(slot, started, plan, la); err != nil {
		return nil, err
	}
	outcomes := map[string]map[string]logOutcome{record.WitnessEurope: eu, record.WitnessLatam: la}
	for _, id := range serviceIDs {
		r.Services[id] = c.combinedService(id, slot, started, plan, r.Witnesses, outcomes, snap)
	}
	return r, nil
}

// secondaryEntry is the second witness's entry: its signed measurement when the
// primary got and verified its answer, else why it did not.
func (c *ciaSim) secondaryEntry(slot, started time.Time, plan v2Plan, la map[string]logOutcome) (record.WitnessEntry, error) {
	if !plan.ran() {
		return record.WitnessEntry{Status: "unavailable", Reason: ptr(plan.reason)}, nil
	}
	peer := c.peerCheck()
	c.mem.peerLast = c.prev.Record // it checks the primary's latest record before it measures
	if plan.answer == lost || plan.answer == rejected {
		return record.WitnessEntry{Status: "unavailable", Reason: ptr(plan.reason)}, nil
	}
	req, err := signRequest(c.signers[record.WitnessEurope], slot, started, c.mem.committed)
	if err != nil {
		return record.WitnessEntry{}, err
	}
	m := c.measured(record.WitnessLatam, slot, started, plan, la, peer)
	entry, err := c.signedEntry(record.WitnessLatam, slot, digestOf(req), m)
	if err != nil {
		return entry, err
	}
	c.mem.committed, err = canonicalDigest(m)
	return entry, err
}

// peerCheck is the secondary's check of the primary's latest published record:
// ok when that record links the one it checked last time, gap when it cannot
// tell (it was away, or this is its first run).
func (c *ciaSim) peerCheck() *record.WitnessPeer {
	verdict := "gap"
	if c.mem.peerLast != "" && c.last != nil && c.last.Prev != nil && c.last.Prev.Record == c.mem.peerLast {
		verdict = "ok"
	}
	return &record.WitnessPeer{Record: ptr(c.prev.Record), SHA256: ptr(c.prev.SHA256), Verdict: verdict}
}

func (c *ciaSim) signedEntry(witness string, slot time.Time, request string, m record.Measured) (record.WitnessEntry, error) {
	n, err := signMeasurement(c.signers[witness], witness, record.FormatTime(slot), request, m)
	return record.WitnessEntry{Status: "ok", Note: &n, Measured: &m}, err
}

// measured is everything a witness measured in a run.
func (c *ciaSim) measured(witness string, slot, started time.Time, plan v2Plan, logs map[string]logOutcome, peer *record.WitnessPeer) record.Measured {
	vp := vantagePoints[witness]
	own := witness == record.WitnessEurope
	down := own && plan.europeDown
	begin, took := started, 5*time.Second
	if !own {
		begin = started.Add(time.Second)
		if plan.answer == partial {
			took = 37 * time.Second
		}
	}
	label := "control"
	if !own {
		label += " " + witness
	}
	m := record.Measured{Witness: witness, Vantage: vp.vantage, Slot: record.FormatTime(slot),
		StartedAt: record.FormatTime(begin), FinishedAt: record.FormatTime(begin.Add(took)),
		Control: controlProbe(label, slot, down), Probes: map[string]record.Probe{}, Logs: map[string]record.WitnessLog{}, Peer: peer}
	for i, id := range serviceIDs {
		code := codeOf(witness, id, slot)
		if down || (plan.answer == partial && !own && i >= 2) {
			code = "vantage" // its own network failed, or it ran out of time before it got to the service
		}
		m.Probes[id] = probeFor(witness, id, slot, code)
	}
	for _, name := range auditLogs {
		m.Logs[name] = measuredLog(logs[name])
	}
	return m
}

// measuredLog is what a witness did with a log, as the record states it.
func measuredLog(o logOutcome) record.WitnessLog {
	code := map[string]string{"unchanged": "ok", "witnessed": "ok", "finding": "finding", "halted": "halted", "error": "vantage"}[o.status]
	l := record.WitnessLog{Code: code, Status: o.status}
	if o.record != "" {
		l.Size, l.Record = ptr(o.size), ptr(o.record)
	}
	if o.root != "" {
		l.Root = ptr(o.root)
	}
	if o.finding != "" {
		l.Finding = ptr(o.finding)
	}
	if o.status == "error" {
		l.Error = ptr(vantageText)
	}
	return l
}

// combinedService is the part of the record that says what the services are:
// the combined verdicts, which anyone can recompute from the measurements.
func (c *ciaSim) combinedService(id string, slot, started time.Time, plan v2Plan, entries map[string]record.WitnessEntry,
	outcomes map[string]map[string]logOutcome, snap *snapshot) record.CIAServiceV2 {
	order := cia.Witnesses([]string{record.WitnessEurope, record.WitnessLatam})
	readings := func(code func(m *record.Measured) string) []cia.Reading {
		out := make([]cia.Reading, len(order))
		for i, w := range order {
			out[i].Witness = w
			if m := entries[w].Measured; m != nil {
				out[i].Code = code(m)
			}
		}
		return out
	}
	p := probeAt(id, slot)
	release := p.release
	if plan.europeDown {
		release = "vantage"
	}
	avail := []record.CIACheckV2{{Healthz: reachability("healthz", "healthz", readings(func(m *record.Measured) string { return m.Probes[id].Code }))}}
	integrity := []record.CIACheckV2{{Release: c.releaseCheck(id, slot, started, release).Release}}
	if id == "status" {
		for _, log := range auditLogs {
			log := log
			avail = append(avail, record.CIACheckV2{Checkpoint: reachability("checkpoint", "checkpoint:"+log,
				readings(func(m *record.Measured) string { return cia.CheckpointCode(m.Logs[log].Code) }))})
			integrity = append(integrity, record.CIACheckV2{Log: evidence(log, order, readings(func(m *record.Measured) string { return m.Logs[log].Code }), outcomes)})
		}
	}
	return record.CIAServiceV2{URL: serviceURL(id), Availability: dimensionV2(avail...), Integrity: dimensionV2(integrity...),
		Confidentiality: dimensionV2(record.CIACheckV2{Incidents: incidentsCheck(id, slot, snap).Incidents})}
}

// reachability combines what the witnesses saw of a service or a log.
func reachability(family, id string, rs []cia.Reading) *record.CombinedCheck {
	res := cia.CombineReachability(family, rs)
	c := &record.CombinedCheck{ID: id, Level: res.Level, Code: res.Code}
	switch res.Code {
	case "vantage":
		c.Error = ptr(vantageText)
	case "regional":
		c.Error = ptr(regionalText(family, rs))
	}
	return c
}

// regionalText says which side failed, and which did not.
func regionalText(family string, rs []cia.Reading) string {
	var failed, failedCode, reached string
	for _, r := range rs {
		level, _ := cia.LevelOfCodeV2(family, r.Code)
		switch {
		case r.Code == "" || level == record.LevelNone:
		case level == record.LevelFail:
			failed, failedCode = r.Witness, r.Code
		default:
			reached = r.Witness
		}
	}
	return fmt.Sprintf("Unreachable from %s (%s); reachable from %s.", regionLabel[failed], failedCode, regionLabel[reached])
}

// evidence combines what the witnesses did with a log: the worst one wins, and
// the finding is the first one's that has a finding or a halt.
func evidence(log string, order []string, rs []cia.Reading, outcomes map[string]map[string]logOutcome) *record.CombinedLog {
	res := cia.CombineEvidence(rs)
	c := &record.CombinedLog{ID: "log:" + log, Level: res.Level, Code: res.Code}
	for _, w := range order {
		if o := outcomes[w][log]; o.finding != "" && (o.status == "finding" || o.status == "halted") {
			c.Finding = ptr(o.finding)
			break
		}
	}
	if res.Code == "vantage" {
		c.Error = ptr(vantageText)
	}
	return c
}

func dimensionV2(checks ...record.CIACheckV2) record.CIADimensionV2 {
	levels := make([]string, len(checks))
	for i, c := range checks {
		levels[i] = c.Level()
	}
	return record.CIADimensionV2{Level: cia.Worst(levels...), Checks: checks}
}
