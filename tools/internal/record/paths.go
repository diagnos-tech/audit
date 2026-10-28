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

// WitnessPath is where the record of a cosignature made at t lives.
func WitnessPath(log string, t time.Time) string {
	return datedPath("data/v1/"+log+"/witness", t, "150405Z.json")
}

// FindingPath is where a finding detected at t lives.
func FindingPath(log string, t time.Time) string {
	return datedPath("data/v1/"+log+"/findings", t, "150405Z.json")
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
	witnessRE   = regexp.MustCompile(`^data/v1/([a-z][a-z0-9-]{0,30})/witness/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{6}Z\.json$`)
	findingRE   = regexp.MustCompile(`^data/v1/([a-z][a-z0-9-]{0,30})/findings/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{6}Z\.json$`)
	timestampRE = regexp.MustCompile(`^data/v1/timestamps/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{2}Z\.json$`)
	tokenRE     = regexp.MustCompile(`^data/v1/timestamps/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{2}Z\.tsr$`)
	indexRE     = regexp.MustCompile(`^data/v1/index/[0-9]{4}/[0-9]{2}\.json$`)
)

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
		return "witness"
	case findingRE.MatchString(path):
		return "finding"
	case timestampRE.MatchString(path):
		return "timestamp"
	case tokenRE.MatchString(path):
		return "token"
	case indexRE.MatchString(path):
		return "index"
	}
	return ciaKind(path)
}
