package check

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// skew is how far a witness's clock may be from the slot: the primary accepts a
// secondary's answer only when its times are within a minute of its own.
const skew = time.Minute

// measuredProblems lists what is wrong with the measurement of one witness
// beyond what the signature says: it is about this slot, its times are
// plausible, it measured exactly the services and logs of the run, each probe
// and log is consistent with its own code, and a witness that lost its own
// network says so in every probe at once.
func measuredProblems(id string, m *record.Measured, run *record.CIARunV2, services, logs []string) []string {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	slot, e1 := record.ParseTime(m.Slot)
	started, e2 := record.ParseTime(m.StartedAt)
	finished, e3 := record.ParseTime(m.FinishedAt)
	runFinished, _ := record.ParseTime(run.FinishedAt)
	switch {
	case m.Witness != id:
		add("measured.witness is %s, the entry is %s", m.Witness, id)
	case m.Slot != run.Slot:
		add("measured.slot %s is not the slot of the run, %s", m.Slot, run.Slot)
	case e1 != nil || e2 != nil || e3 != nil:
		add("slot, startedAt and finishedAt must be RFC 3339 UTC times")
	case finished.Before(started) || started.Before(slot.Add(-skew)) || finished.After(runFinished.Add(skew)):
		add("measured from %s to %s, which does not fit slot %s and a run that finished at %s (clock skew above %s)",
			m.StartedAt, m.FinishedAt, m.Slot, run.FinishedAt, skew)
	}
	if !vantageRE.MatchString(m.Vantage) {
		add("vantage %q is not provider:region (for example scaleway:fr-par)", m.Vantage)
	}
	if c := m.Control; c != nil && !hostRE.MatchString(c.Host) {
		add("control host %q is not a host name", c.Host)
	}
	if !sameKeys(m.Probes, services) {
		add("probes are %v, the services of the run are %v", sortedKeys(m.Probes), services)
	}
	if !sameKeys(m.Logs, logs) {
		add("logs are %v, the logs of the run are %v", sortedKeys(m.Logs), logs)
	}
	for _, s := range sortedKeys(m.Probes) {
		problems = append(problems, prefixed("probe "+s, probeProblems(m.Probes[s]))...)
	}
	for _, l := range sortedKeys(m.Logs) {
		problems = append(problems, prefixed("log "+l, witnessLogProblems(l, m.Logs[l]))...)
	}
	problems = append(problems, vantageProblems(m)...)
	return append(problems, peerShapeProblems(id, m.Peer)...)
}

func prefixed(prefix string, problems []string) []string {
	for i := range problems {
		problems[i] = prefix + ": " + problems[i]
	}
	return problems
}

func sameKeys[V any](m map[string]V, want []string) bool {
	return slices.Equal(sortedKeys(m), want)
}

// vantageProblems applies INCIDENTS-CONTRACT §9 to one witness. When its control
// probe failed and every probe failed at the transport level, its own network
// is at fault and nothing is an outage: that run must be recorded as not
// measured (code vantage) throughout. And a witness whose control probe failed
// either measured nothing or something, never half: a probe that is not
// measured among probes that are cannot be explained by a lost network (it can
// by a lack of time, which only a working control probe allows).
func vantageProblems(m *record.Measured) []string {
	if m.Control == nil || m.Control.OK {
		return nil
	}
	transport, vantage, total := 0, 0, 0
	for _, p := range m.Probes {
		total++
		switch p.Code {
		case "timeout", "connect-error", "tls-error":
			transport++
		case "vantage":
			vantage++
		}
	}
	for _, l := range m.Logs {
		total++
		if l.Code == "vantage" {
			vantage++
		}
	}
	switch {
	case transport == len(m.Probes) && len(m.Probes) > 0:
		return []string{"recorded as outages while the control probe failed: every probe failed at the transport level, which is a vantage failure (code vantage), not an outage"}
	case vantage != 0 && vantage != total:
		return []string{"some probes and logs are not measured and others are, although the control probe failed: a vantage failure leaves none of them measured"}
	}
	return nil
}

// peerShapeProblems: the primary witness has no peer to check; any other
// witness reads the primary's latest published record, and says what came of it.
func peerShapeProblems(id string, p *record.WitnessPeer) []string {
	switch {
	case id == record.WitnessEurope && p != nil:
		return []string{"the primary witness has no peer to check"}
	case id == record.WitnessEurope:
		return nil
	case p == nil:
		return []string{"a secondary witness checks the primary's latest record and says what came of it (peer)"}
	}
	switch p.Verdict {
	case "ok", "mismatch", "gap":
		if p.Record == nil || p.SHA256 == nil {
			return []string{"a peer verdict of " + p.Verdict + " names the record it read and its digest"}
		}
	case "unavailable":
		if p.Record != nil || p.SHA256 != nil {
			return []string{"a peer that could not be read names no record"}
		}
	default:
		return []string{fmt.Sprintf("peer verdict %q is not ok, gap, mismatch or unavailable", p.Verdict)}
	}
	if p.Record != nil && record.Kind(*p.Record) != "cia-run" {
		return []string{*p.Record + " is not a run record path"}
	}
	return nil
}

// checkPeer compares a secondary witness's check of the primary's record with
// the record: a verdict of ok says it saw the bytes the repository has; a
// mismatch is a signed statement that the published history changed, which the
// report shows as a warning (the change event is where it is told) because an
// immutable record cannot be made to pass by editing it.
func checkPeer(rd *ciaReader, run string, id string, p *record.WitnessPeer, r *Report) {
	if p == nil {
		return
	}
	if p.Verdict == "mismatch" {
		r.warn("peer "+id, "%s reports that the history published as %s changed after it was archived", id, deref(p.Record))
		return
	}
	if p.Verdict != "ok" || p.Record == nil || p.SHA256 == nil {
		return
	}
	if *p.Record >= run {
		r.fail("peer "+id, "checks %s, which is not before this run", *p.Record)
		return
	}
	data, err := rd.read(*p.Record)
	switch {
	case err != nil:
		r.pass("peer "+id, "checked %s, which is outside these files", *p.Record)
	case sum(data) != *p.SHA256:
		r.fail("peer "+id, "says it saw %s as %s, but the file hashes to %s", *p.Record, short(*p.SHA256), short(sum(data)))
	default:
		r.pass("peer "+id, "saw %s as it is published", *p.Record)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// logNames lists the transparency logs a run names, from its checkpoint and
// log checks, sorted.
func logNames(v2 *record.CIARunV2) []string {
	seen := map[string]bool{}
	for _, svc := range v2.Services {
		for _, c := range svc.Availability.Checks {
			if c.Checkpoint != nil {
				seen[strings.TrimPrefix(c.Checkpoint.ID, "checkpoint:")] = true
			}
		}
		for _, c := range svc.Integrity.Checks {
			if c.Log != nil {
				seen[strings.TrimPrefix(c.Log.ID, "log:")] = true
			}
		}
	}
	return sortedKeys(seen)
}
