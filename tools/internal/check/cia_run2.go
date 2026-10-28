package check

import (
	"fmt"
	"slices"
	"strings"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// checkRunV2 checks what the JSON Schema cannot say about a cia-run/v2 record
// (ARCH-V2 §8): every witness's entry and signed measurement, the combined
// verdicts against what the measurements allow, the structure and order of the
// checks, the files the measurements name, and the split view that two witnesses
// may have exposed. The record's name and slot were checked already.
func checkRunV2(rd *ciaReader, keys *Keyring, rec *record.CIARun, path string, r *Report) {
	v2 := rec.V2
	checkRunIncidents(rec, r)
	checkWitnessEntries(rd, keys, v2, path, r)
	checkRunServicesV2(rec, r)
	if problems := splitViewProblems(v2); len(problems) > 0 {
		r.fail("split view", "%s", strings.Join(problems, "; "))
	}
	checkWitnessLinks(rd, v2, r)
}

// checkWitnessEntries checks the entries of the witnesses one by one.
func checkWitnessEntries(rd *ciaReader, keys *Keyring, v2 *record.CIARunV2, path string, r *Report) {
	if e, ok := v2.Witnesses[record.WitnessEurope]; !ok || e.Status != "ok" {
		r.fail("witnesses", "the primary witness (%s) writes the record: its entry is required, and it measured", record.WitnessEurope)
		return
	}
	services, logs := sortedKeys(v2.Services), logNames(v2)
	for _, id := range cia.Witnesses(sortedKeys(v2.Witnesses)) {
		e := v2.Witnesses[id]
		if problem := entryProblem(id, e); problem != "" {
			r.fail("witness "+id, "%s", problem)
			continue
		}
		if e.Status != "ok" {
			r.pass("witness "+id, "not measured in this run (%s); this is not an outage of any service", *e.Reason)
			continue
		}
		if problems := measuredProblems(id, e.Measured, v2, services, logs); len(problems) > 0 {
			r.fail("witness "+id, "%s", strings.Join(problems, "; "))
			continue
		}
		r.pass("witness "+id, "measured %d services and %d logs from %s", len(e.Measured.Probes), len(e.Measured.Logs), e.Measured.Vantage)
		checkMeasurementNote(keys, id, e, v2.Slot, r)
		checkPeer(rd, path, id, e.Measured.Peer, r)
	}
}

// entryProblem checks an entry on its own: a measured witness has its note and
// its measurement, a missing one has a reason and neither.
func entryProblem(id string, e record.WitnessEntry) string {
	reasons := []string{record.ReasonTimeout, record.ReasonUnreachable, record.ReasonRejected, record.ReasonSignature, record.ReasonInvalid, record.ReasonSkew, record.ReasonOff}
	switch {
	case !witnessRE.MatchString(id):
		return fmt.Sprintf("%q is not a witness id", id)
	case id != record.WitnessEurope && slices.Contains([]string{"cia", "index", "timestamps", "witnesses"}, id):
		return fmt.Sprintf("%q is not a witness id", id)
	case e.Status == "ok" && (e.Reason != nil || e.Note == nil || e.Measured == nil):
		return "a measured witness has its note and its measurement, and no reason"
	case e.Status == "unavailable" && (e.Reason == nil || !slices.Contains(reasons, *e.Reason) || e.Note != nil || e.Measured != nil):
		return fmt.Sprintf("an unavailable witness has a reason (%s) and neither a note nor a measurement", strings.Join(reasons, ", "))
	case e.Status != "ok" && e.Status != "unavailable":
		return fmt.Sprintf("status %q is neither ok nor unavailable", e.Status)
	}
	return ""
}

// checkRunServicesV2 checks the structure of every service, the order of its
// checks and the levels their codes require, as for cia-run/v1, and then that
// the combined verdicts are what the measurements give.
func checkRunServicesV2(rec *record.CIARun, r *Report) {
	for _, id := range sortedKeys(rec.Services) {
		svc := rec.Services[id]
		var problems []string
		for _, name := range record.Dimensions {
			problems = append(problems, dimensionProblemsFor(v2Rules, name, svc.Dimension(name))...)
		}
		if len(problems) == 0 {
			problems = combinedProblems(rec.V2, id)
		}
		if len(problems) > 0 {
			r.fail("service "+id, "%s", strings.Join(problems, "; "))
			continue
		}
		r.pass("service "+id, "availability %s, integrity %s, confidentiality %s, as the witnesses' measurements combine",
			svc.Availability.Level, svc.Integrity.Level, svc.Confidentiality.Level)
	}
}

// checkWitnessLinks follows the files a measurement names: the witness record
// and the finding of each log are in the namespace of the witness that made
// them, exist, are about that log and agree with the size and root it reports.
func checkWitnessLinks(rd *ciaReader, v2 *record.CIARunV2, r *Report) {
	for _, id := range cia.Witnesses(sortedKeys(v2.Witnesses)) {
		m := v2.Witnesses[id].Measured
		if m == nil {
			continue
		}
		for _, log := range sortedKeys(m.Logs) {
			if problem := witnessLogLinkProblem(rd, id, log, m.Logs[log]); problem != "" {
				r.fail("links "+id, "log:%s: %s", log, problem)
			}
		}
	}
}

func witnessLogLinkProblem(rd *ciaReader, id, log string, l record.WitnessLog) string {
	if l.Record != nil {
		if wid, name, ok := record.WitnessOf(*l.Record); !ok || wid != id || name != log {
			return fmt.Sprintf("%s is not a witness record of %s for log %s", *l.Record, id, log)
		}
		var w record.Witness
		data, err := rd.read(*l.Record)
		if err != nil {
			return err.Error()
		}
		if err := record.Decode(data, "witness/v1", &w); err != nil {
			return fmt.Sprintf("%s: %v", *l.Record, err)
		}
		switch {
		case w.Log != log || (l.Size != nil && w.Checkpoint.Size != *l.Size):
			return fmt.Sprintf("%s is the record of log %s at size %d, not %s at %v", *l.Record, w.Log, w.Checkpoint.Size, log, derefSize(l.Size))
		case l.Root != nil && l.Status != "finding" && w.Checkpoint.Root != *l.Root:
			// At a finding the root is the second one the log signed, which differs from the record's by definition.
			return fmt.Sprintf("%s has root %s, the measurement says %s", *l.Record, short(w.Checkpoint.Root), short(*l.Root))
		}
	}
	if l.Finding != nil {
		if wid, name, ok := record.WitnessOf(*l.Finding); !ok || wid != id || name != log {
			return fmt.Sprintf("%s is not a finding of %s about log %s", *l.Finding, id, log)
		}
		var f record.Finding
		data, err := rd.read(*l.Finding)
		if err != nil {
			return err.Error()
		}
		if err := record.Decode(data, "finding/v1", &f); err != nil {
			return fmt.Sprintf("%s: %v", *l.Finding, err)
		}
		if f.Log != log {
			return fmt.Sprintf("%s is a finding about log %s", *l.Finding, f.Log)
		}
	}
	return ""
}
