package cia

import (
	"strings"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// regionalFailure says which witness failed in a run whose availability of the
// service is regional: the first check at the dimension's level has code
// regional, and the witness whose probe (healthz) or log (checkpoint) failed
// is the region the service could not be reached from. ok is false for a run
// that is not regional.
func regionalFailure(r *record.CIARun, service string) (witness string, ok bool) {
	svc, found := r.Services[service]
	if !found || r.V2 == nil {
		return "", false
	}
	var check record.CIACheck
	for _, c := range svc.Availability.Checks {
		if c.Level() == svc.Availability.Level {
			check = c
			break
		}
	}
	if check.Code() != "regional" {
		return "", false
	}
	for _, w := range Witnesses(witnessKeys(r.V2)) {
		m := r.V2.Witnesses[w].Measured
		if m != nil && failed(m, service, check.ID()) {
			return w, true
		}
	}
	return "", false
}

func failed(m *record.Measured, service, checkID string) bool {
	if checkID == "healthz" {
		level, _ := LevelOfCodeV2("healthz", m.Probes[service].Code)
		return level == record.LevelFail
	}
	log, has := m.Logs[strings.TrimPrefix(checkID, "checkpoint:")]
	return has && log.Code == "unreachable"
}

func witnessKeys(r *record.CIARunV2) []string {
	ids := make([]string, 0, len(r.Witnesses))
	for w := range r.Witnesses {
		ids = append(ids, w)
	}
	return ids
}
