package check

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// ciaRun reads one run record and checks what the JSON Schema cannot say
// (CONTRACTS §7.2): the file name is the slot, every check has the level its
// code requires, a dimension is as bad as its worst check, and the checks come
// in the contract's order.
func ciaRun(src record.Source, keys *Keyring, rd *ciaReader, path string) (*record.CIARun, []byte, *Report) {
	r := &Report{Subject: path}
	data, err := src.Read(path)
	if err != nil {
		r.fail("read", "%v", err)
		return nil, nil, r
	}
	rec, err := record.DecodeRun(data)
	if err != nil {
		r.fail("format", "%v", err)
		return nil, data, r
	}
	slot, err := record.ParseTime(rec.Slot)
	started, err2 := record.ParseTime(rec.StartedAt)
	finished, err3 := record.ParseTime(rec.FinishedAt)
	switch {
	case err != nil || err2 != nil || err3 != nil:
		r.fail("slot", "slot, startedAt and finishedAt must be RFC 3339 UTC times")
		return nil, data, r
	case record.CIARunPath(slot) != path:
		r.fail("slot", "the record of slot %s belongs at %s", rec.Slot, record.CIARunPath(slot))
		return nil, data, r
	case !slot.Equal(record.SlotOf(slot)) || !record.SlotOf(started).Equal(slot):
		r.fail("slot", "slot %s is not the five-minute slot of startedAt %s", rec.Slot, rec.StartedAt)
	case finished.Before(started):
		r.fail("slot", "finishedAt %s is before startedAt %s", rec.FinishedAt, rec.StartedAt)
	default:
		r.pass("slot", "%s, run of %s", rec.Slot, finished.Sub(started))
	}
	if rec.V2 != nil {
		checkRunV2(rd, keys, rec, path, r)
		return rec, data, r
	}
	if rec.Vantage != "" && !vantageRE.MatchString(rec.Vantage) {
		r.fail("vantage", "%q is not provider:region (for example scaleway:fr-par)", rec.Vantage)
	}
	checkRunIncidents(rec, r)
	checkRunServices(rec, r)
	checkVantage(rec, r)
	return rec, data, r
}

var vantageRE = regexp.MustCompile(`^[a-z][a-z0-9-]*:[a-z0-9][a-z0-9-]*$`)

var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// checkVantage applies INCIDENTS-CONTRACT §9: a run in which the auditor's own
// network failed records every network check as not measured (level none, code
// vantage) and says so in its control probe; and a run whose control probe failed
// while every service failed at the transport level is not an outage.
func checkVantage(rec *record.CIARun, r *Report) {
	if c := rec.Control; c != nil && !hostRE.MatchString(c.Host) {
		r.fail("control", "host %q is not a host name", c.Host)
		return
	}
	any, all, transport, services := false, true, 0, 0
	for _, svc := range rec.Services {
		services++
		for _, name := range record.Dimensions {
			for _, c := range svc.Dimension(name).Checks {
				if network(c) {
					any, all = any || c.Code() == "vantage", all && c.Level() == record.LevelNone && c.Code() == "vantage"
				}
				if h := c.Healthz; h != nil && (h.Code == "timeout" || h.Code == "connect-error" || h.Code == "tls-error") {
					transport++
				}
			}
		}
	}
	controlFailed := rec.Control != nil && !rec.Control.OK
	switch {
	case any && !all:
		r.fail("vantage", "some network checks have code vantage and others do not: a vantage failure leaves none of them measured")
	case any && !controlFailed:
		r.fail("vantage", "network checks are recorded as a vantage failure, but the control probe did not fail")
	case !any && controlFailed && transport == services:
		r.fail("vantage", "recorded as an outage while the control probe failed: a vantage failure, whose network checks have code vantage")
	case any:
		r.pass("vantage", "the control probe failed: nothing was measured, no outage")
	}
}

// network says whether a check reads the network (healthz, checkpoint, release
// and log checks); the incidents check reads the repository.
func network(c record.CIACheck) bool { return c.Incidents == nil }

func checkRunIncidents(rec *record.CIARun, r *Report) {
	in := rec.Incidents
	switch {
	case in.Source == "none" && (in.Commit != nil || in.ReadAt != nil || in.Snapshot != nil):
		r.fail("incidents", "source none cannot name a commit, a read time or a snapshot")
	case in.Source == "github" && (in.Commit == nil || in.ReadAt == nil):
		r.fail("incidents", "source github must name the commit and the time it was read")
	default:
		r.pass("incidents", "read from %s", in.Source)
	}
}

func checkRunServices(rec *record.CIARun, r *Report) {
	ids := make([]string, 0, len(rec.Services))
	for id := range rec.Services {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		svc := rec.Services[id]
		var problems []string
		for _, name := range record.Dimensions {
			problems = append(problems, dimensionProblems(name, svc.Dimension(name))...)
		}
		if len(problems) > 0 {
			r.fail("service "+id, "%s", strings.Join(problems, "; "))
			continue
		}
		r.pass("service "+id, "availability %s, integrity %s, confidentiality %s",
			svc.Availability.Level, svc.Integrity.Level, svc.Confidentiality.Level)
	}
}

// codeRules are the parts of a check's rules that differ between the versions
// of the run record: the table of codes and levels, and the fields a code needs.
type codeRules struct {
	levelOf func(checkID, code string) (string, bool)
	fields  func(record.CIACheck) []string
}

var (
	v1Rules = codeRules{cia.LevelOfCode, checkFields}
	v2Rules = codeRules{cia.LevelOfCodeV2, v2FieldProblems}
)

// dimensionProblems lists what is wrong with one dimension of one service of a
// cia-run/v1 record.
func dimensionProblems(name string, d record.CIADimension) []string {
	return dimensionProblemsFor(v1Rules, name, d)
}

func dimensionProblemsFor(rules codeRules, name string, d record.CIADimension) []string {
	var problems []string
	levels := make([]string, len(d.Checks))
	for i, c := range d.Checks {
		levels[i] = c.Level()
		if cia.DimensionOfCheck(c.ID()) != name {
			problems = append(problems, fmt.Sprintf("%s: check %q does not belong to %s", name, c.ID(), name))
			continue
		}
		want, ok := rules.levelOf(c.ID(), c.Code())
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s: %q is not a code of %s", name, c.Code(), c.ID()))
		case want != c.Level():
			problems = append(problems, fmt.Sprintf("%s: %s with code %s must be %s, not %s", name, c.ID(), c.Code(), want, c.Level()))
		}
		problems = append(problems, rules.fields(c)...)
	}
	if !cia.Valid(d.Level) || d.Level != cia.Worst(levels...) {
		problems = append(problems, fmt.Sprintf("%s: level %s is not the worst of its checks (%s)", name, d.Level, cia.Worst(levels...)))
	}
	return append(problems, orderProblems(name, d.Checks)...)
}

// orderProblems checks the order of §7.2: availability is healthz then the
// checkpoints, integrity the release then the logs, sorted by log name.
func orderProblems(name string, checks []record.CIACheck) []string {
	first, prefix := map[string]string{"availability": "healthz", "integrity": "release", "confidentiality": "incidents"}[name],
		map[string]string{"availability": "checkpoint:", "integrity": "log:"}[name]
	if len(checks) == 0 || checks[0].ID() != first {
		return []string{fmt.Sprintf("%s: the first check must be %s", name, first)}
	}
	var rest []string
	for _, c := range checks[1:] {
		if prefix == "" || !strings.HasPrefix(c.ID(), prefix) {
			return []string{fmt.Sprintf("%s: unexpected check %s after %s", name, c.ID(), first)}
		}
		rest = append(rest, c.ID())
	}
	if !slices.IsSorted(rest) || len(slices.Compact(slices.Clone(rest))) != len(rest) {
		return []string{fmt.Sprintf("%s: the %s checks must be sorted by name, once each", name, strings.TrimSuffix(prefix, ":"))}
	}
	return nil
}
