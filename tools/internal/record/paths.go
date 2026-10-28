package record

import (
	"fmt"
	"regexp"
	"time"
)

// TimeLayout is RFC 3339 in UTC with second precision, the only time format
// the data files use.
const TimeLayout = "2006-01-02T15:04:05Z"

// ParseTime parses a data-file time, refusing anything but TimeLayout.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(TimeLayout, s)
	if err != nil || t.Format(TimeLayout) != s {
		return time.Time{}, fmt.Errorf("time %q is not RFC 3339 UTC with seconds", s)
	}
	return t, nil
}

// FormatTime renders t in TimeLayout.
func FormatTime(t time.Time) string { return t.UTC().Format(TimeLayout) }

// WitnessPath is where the record of a cosignature made by the primary witness
// at t lives.
func WitnessPath(log string, t time.Time) string { return WitnessPathOf(WitnessEurope, log, t) }

// FindingPath is where a finding detected by the primary witness at t lives.
func FindingPath(log string, t time.Time) string { return FindingPathOf(WitnessEurope, log, t) }

// WitnessPathOf is where the record of a cosignature made by the named witness
// at t lives. The primary witness (europe) keeps its records where they have
// always been, data/v1/<log>/witness; every other witness has a namespace of
// its own, data/v1/witnesses/<witness>/<log>/witness.
func WitnessPathOf(witness, log string, t time.Time) string {
	return datedPath(NamespaceDir(witness)+log+"/witness", t, "150405Z.json")
}

// FindingPathOf is where a finding detected by the named witness at t lives.
func FindingPathOf(witness, log string, t time.Time) string {
	return datedPath(NamespaceDir(witness)+log+"/findings", t, "150405Z.json")
}

// NamespaceDir is the directory, with a trailing slash, under which a witness
// keeps its records.
func NamespaceDir(witness string) string {
	if witness == WitnessEurope {
		return "data/v1/"
	}
	return "data/v1/witnesses/" + witness + "/"
}

// TimestampPath is the hourly record of the hour that contains t.
func TimestampPath(t time.Time) string {
	return datedPath("data/v1/timestamps", t, "15Z.json")
}

// TokenPath is the raw RFC 3161 response next to TimestampPath(t).
func TokenPath(t time.Time) string {
	return datedPath("data/v1/timestamps", t, "15Z.tsr")
}

// IndexPath is the month index of the month that contains t.
func IndexPath(t time.Time) string {
	return "data/v1/index/" + t.UTC().Format("2006/01") + ".json"
}

// Month names the month that contains t, as months in latest.json do.
func Month(t time.Time) string { return t.UTC().Format("2006-01") }

func datedPath(dir string, t time.Time, name string) string {
	return dir + "/" + t.UTC().Format("2006/01/02/") + t.UTC().Format(name)
}

var (
	witnessRE   = regexp.MustCompile(`^data/v1/(?:witnesses/([a-z][a-z0-9-]{1,15})/)?([a-z][a-z0-9-]{0,30})/witness/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{6}Z\.json$`)
	findingRE   = regexp.MustCompile(`^data/v1/(?:witnesses/([a-z][a-z0-9-]{1,15})/)?([a-z][a-z0-9-]{0,30})/findings/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{6}Z\.json$`)
	timestampRE = regexp.MustCompile(`^data/v1/timestamps/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{2}Z\.json$`)
	tokenRE     = regexp.MustCompile(`^data/v1/timestamps/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{2}Z\.tsr$`)
	indexRE     = regexp.MustCompile(`^data/v1/index/[0-9]{4}/[0-9]{2}\.json$`)
)

// reservedLogs are names under data/v1 that are not transparency logs.
var reservedLogs = map[string]bool{"cia": true, "index": true, "timestamps": true, "witnesses": true}

// WitnessOf splits the path of a witness record or a finding into the witness
// that made it and the log it is about. ok is false for a path that is neither,
// including one in the namespace of europe (the primary witness never has one)
// and one that names a log called like a directory of data/v1.
func WitnessOf(path string) (witness, log string, ok bool) {
	m := witnessRE.FindStringSubmatch(path)
	if m == nil {
		m = findingRE.FindStringSubmatch(path)
	}
	if m == nil || reservedLogs[m[2]] || m[1] == WitnessEurope {
		return "", "", false
	}
	if m[1] == "" {
		return WitnessEurope, m[2], true
	}
	return m[1], m[2], true
}

// Kind tells what a repository path holds, by its name alone: "witness",
// "finding", "timestamp", "token", "index", "state", "latest", the kinds of
// the CIA layout ("cia-run", "cia-incidents", "cia-day", "cia-summary",
// "cia-latest", "cia-incidents-view", "cia-incident-event", "cia-changes",
// "cia-changes-recent", "sync", "release-verdict", "release-manifest",
// "release-evidence"), or "" for a path that has no
// place under data/.
func Kind(path string) string {
	switch {
	case path == "data/v1/state.json":
		return "state"
	case path == "data/v1/latest.json":
		return "latest"
	case witnessRE.MatchString(path):
		if _, _, ok := WitnessOf(path); ok {
			return "witness"
		}
		return ""
	case findingRE.MatchString(path):
		if _, _, ok := WitnessOf(path); ok {
			return "finding"
		}
		return ""
	case timestampRE.MatchString(path):
		return "timestamp"
	case tokenRE.MatchString(path):
		return "token"
	case indexRE.MatchString(path):
		return "index"
	}
	return ciaKind(path)
}
