package cia

import (
	"slices"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// Reading is what one witness made of one check in one run: the code it
// measured, or "" when it measured nothing (it was silent, or unavailable).
type Reading struct {
	Witness string
	Code    string
}

// Witnesses puts witness ids in the order readings are taken in and ties are
// broken: the primary witness first, the others by id.
func Witnesses(ids []string) []string {
	out := slices.Clone(ids)
	slices.SortFunc(out, func(a, b string) int {
		switch {
		case a == b:
			return 0
		case a == record.WitnessEurope:
			return -1
		case b == record.WitnessEurope:
			return 1
		case a < b:
			return -1
		}
		return 1
	})
	return out
}

// CombineReachability is the verdict of a reachability check (healthz, and the
// checkpoint of a log) over what the witnesses saw. A service is down only
// when the witnesses that measured it agree:
//
//   - nobody measured: not measured (none, vantage);
//   - one witness measured: its verdict stands, because its own retry is the
//     confirmation;
//   - several measured, and every one of them failed: fail, with the code of the
//     first;
//   - several measured, and some failed while others did not: warn, regional;
//   - otherwise the worst level, with the code of the first witness at it.
//
// A witness that did not measure is neutral: it neither confirms nor
// contradicts. family is "healthz" or "checkpoint", the table the codes
// belong to. The readings must be in the order of Witnesses.
func CombineReachability(family string, readings []Reading) Result {
	var measuring []Result
	failed := 0
	for _, r := range readings {
		level, ok := LevelOfCodeV2(family, r.Code)
		if r.Code == "" || !ok || level == record.LevelNone {
			continue
		}
		measuring = append(measuring, Result{Level: level, Code: r.Code})
		if level == record.LevelFail {
			failed++
		}
	}
	switch {
	case len(measuring) == 0:
		return Result{Level: record.LevelNone, Code: "vantage"}
	case failed > 0 && failed < len(measuring):
		return Result{Level: record.LevelWarn, Code: "regional"}
	}
	return firstWorst(measuring)
}

// CombineEvidence is the verdict of an evidence check (what the witnesses did
// with a transparency log): the worst witness wins, because a finding or a halt
// seen from one place is a finding, and a split view shown to one region only
// is what a second witness exists to catch. The first witness at the worst
// level gives the code; ties go to the primary.
func CombineEvidence(readings []Reading) Result {
	var all []Result
	for _, r := range readings {
		if level, ok := LevelOfCodeV2("log", r.Code); r.Code != "" && ok {
			all = append(all, Result{Level: level, Code: r.Code})
		}
	}
	if len(all) == 0 {
		return Result{Level: record.LevelNone, Code: "vantage"}
	}
	return firstWorst(all)
}

// firstWorst is the first of the results that has the worst level.
func firstWorst(results []Result) Result {
	levels := make([]string, len(results))
	for i, r := range results {
		levels[i] = r.Level
	}
	worst := Worst(levels...)
	for _, r := range results {
		if r.Level == worst {
			return r
		}
	}
	return Result{Level: worst}
}

// CheckpointCode is the code one witness gives the checkpoint check of a log,
// from the code it gave the log: the checkpoint was reachable unless the log
// says otherwise, even when the log is halted by a finding.
func CheckpointCode(logCode string) string {
	switch logCode {
	case "":
		return ""
	case "unreachable", "vantage":
		return logCode
	}
	return "ok"
}
