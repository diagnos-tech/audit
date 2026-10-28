package cia

import (
	"strings"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

var rank = map[string]int{record.LevelNone: 0, record.LevelOK: 1, record.LevelWarn: 2, record.LevelFail: 3}

// Worst returns the worst level of the arguments, fail > warn > ok > none. The
// worst of nothing is none.
func Worst(levels ...string) string {
	worst := record.LevelNone
	for _, l := range levels {
		if rank[l] > rank[worst] {
			worst = l
		}
	}
	return worst
}

// Valid reports whether l is one of the four levels.
func Valid(l string) bool { _, ok := rank[l]; return ok }

// Letter is how day and window strings write a level: o, w, f, or - for none.
func Letter(level string) byte {
	switch level {
	case record.LevelOK:
		return 'o'
	case record.LevelWarn:
		return 'w'
	case record.LevelFail:
		return 'f'
	}
	return '-'
}

// codeLevels is the table of CONTRACTS §7.2, by check family.
var codeLevels = map[string]map[string]string{
	"healthz": {
		"ok": "ok", "retried": "ok", "slow": "warn", "tls-expiring": "warn",
		"timeout": "fail", "connect-error": "fail", "tls-error": "fail", "http-status": "fail",
		"content-type": "fail", "invalid-body": "fail", "wrong-service": "fail", "wrong-environment": "fail",
		"vantage": "none",
	},
	"checkpoint": {"ok": "ok", "unreachable": "fail", "vantage": "none"},
	"release": {
		"verified": "ok", "pending": "warn", "unverified": "warn", "unsigned": "warn", "unmonitored": "warn",
		"digest-mismatch": "fail", "claim-mismatch": "fail", "signature-invalid": "fail",
		"provenance-invalid": "fail", "served-mismatch": "fail", "unreachable": "none", "vantage": "none",
	},
	"log":       {"ok": "ok", "log-error": "warn", "finding": "fail", "halted": "fail", "unreachable": "none", "vantage": "none"},
	"incidents": {"clear": "ok", "incident-low": "warn", "invalid": "warn", "incident-high": "fail", "unavailable": "none"},
}

// LevelOfCode is the level a check with this id and code must have. ok is
// false for a code the check does not allow.
func LevelOfCode(checkID, code string) (string, bool) {
	family, _, _ := strings.Cut(checkID, ":")
	level, ok := codeLevels[family][code]
	return level, ok
}

// v2Codes are the codes a cia-run/v2 record adds to the table: regional, the
// verdict of a reachability check that one witness failed and another did not,
// and challenged, a probe the edge answered with a bot challenge, which says
// nothing about the service.
var v2Codes = map[string]map[string]string{
	"healthz":    {"challenged": "none", "regional": "warn"},
	"checkpoint": {"regional": "warn"},
}

// LevelOfCodeV2 is LevelOfCode for the checks of a cia-run/v2 record.
func LevelOfCodeV2(checkID, code string) (string, bool) {
	if level, ok := LevelOfCode(checkID, code); ok {
		return level, true
	}
	family, _, _ := strings.Cut(checkID, ":")
	level, ok := v2Codes[family][code]
	return level, ok
}

// DimensionOfCheck says which dimension a check id belongs to, "" if none.
func DimensionOfCheck(checkID string) string {
	family, _, _ := strings.Cut(checkID, ":")
	switch family {
	case "healthz", "checkpoint":
		return "availability"
	case "release", "log":
		return "integrity"
	case "incidents":
		return "confidentiality"
	}
	return ""
}
