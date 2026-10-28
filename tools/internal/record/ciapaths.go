package record

import (
	"fmt"
	"regexp"
	"time"
)

// SlotLength is the interval one auditor run covers.
const SlotLength = 5 * time.Minute

// DayLayout names a UTC day, as cia-day and cia-summary do.
const DayLayout = "2006-01-02"

// CIARunPath is where the run record of the slot starting at t lives.
func CIARunPath(t time.Time) string { return slotPath("data/v1/cia/runs", t) }

// CIAIncidentsPath is where the incidents snapshot read in the slot at t lives.
func CIAIncidentsPath(t time.Time) string { return slotPath("data/v1/cia/incidents", t) }

// CIADayPath is the day file of the UTC day that contains t.
func CIADayPath(t time.Time) string {
	return "data/v1/cia/days/" + t.UTC().Format("2006/01/02") + ".json"
}

// ReleaseDir is the directory of one release's verdict and evidence.
func ReleaseDir(service, digest string) string {
	return "data/v1/cia/releases/" + service + "/" + digest
}

// Fixed paths of the CIA views and the mirror cursor.
const (
	CIASummaryPath       = "data/v1/cia/summary.json"
	CIALatestPath        = "data/v1/cia/latest.json"
	CIAIncidentsViewPath = "data/v1/cia/incidents.json"
	CIAChangesPath       = "data/v1/cia/changes.json"
	CIARecentPath        = "data/v1/cia/changes-recent.json"
	SyncPath             = "data/v1/sync.json"
	SignersPath          = "keys/signers.json"
)

// CIAIncidentEventPath is the file of event seq of the automatic incident id,
// under the UTC day of the run that wrote it.
func CIAIncidentEventPath(id string, seq int, at time.Time) string {
	return fmt.Sprintf("data/v1/cia/incidents/events/%s/%s-%d.json", at.UTC().Format("2006/01/02"), id, seq)
}

func slotPath(dir string, t time.Time) string {
	return dir + "/" + t.UTC().Format("2006/01/02/") + t.UTC().Format("1504") + "Z.json"
}

// SlotOf is the start of the five-minute slot that contains t.
func SlotOf(t time.Time) time.Time { return t.UTC().Truncate(SlotLength) }

var (
	ciaRunRE       = regexp.MustCompile(`^data/v1/cia/runs/[0-9]{4}/[0-9]{2}/[0-9]{2}/([01][0-9]|2[0-3])[0-5][05]Z\.json$`)
	ciaIncidentsRE = regexp.MustCompile(`^data/v1/cia/incidents/[0-9]{4}/[0-9]{2}/[0-9]{2}/([01][0-9]|2[0-3])[0-5][05]Z\.json$`)
	ciaEventRE     = regexp.MustCompile(`^data/v1/cia/incidents/events/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{4}-[0-9]{2}-[0-9]{2}-auto-[a-z][a-z0-9-]{0,30}-[ai]-[0-9]{4}-[1-9][0-9]{0,3}\.json$`)
	ciaDayRE       = regexp.MustCompile(`^data/v1/cia/days/[0-9]{4}/[0-9]{2}/[0-9]{2}\.json$`)
	releaseRE      = regexp.MustCompile(`^data/v1/cia/releases/([a-z][a-z0-9-]{0,30})/([0-9a-f]{64})/(verdict\.json|manifest\.json|manifest\.json\.sig|provenance\.sigstore\.json)$`)
)

// ciaKind classifies the paths of the CIA layout; "" if the path is not one.
func ciaKind(path string) string {
	switch {
	case path == CIASummaryPath:
		return "cia-summary"
	case path == CIALatestPath:
		return "cia-latest"
	case path == CIAIncidentsViewPath:
		return "cia-incidents-view"
	case path == CIAChangesPath:
		return "cia-changes"
	case path == CIARecentPath:
		return "cia-changes-recent"
	case path == SyncPath:
		return "sync"
	case ciaEventRE.MatchString(path):
		return "cia-incident-event"
	case ciaRunRE.MatchString(path):
		return "cia-run"
	case ciaIncidentsRE.MatchString(path):
		return "cia-incidents"
	case ciaDayRE.MatchString(path):
		return "cia-day"
	}
	if m := releaseRE.FindStringSubmatch(path); m != nil {
		switch m[3] {
		case "verdict.json":
			return "release-verdict"
		case "manifest.json":
			return "release-manifest"
		}
		return "release-evidence"
	}
	return ""
}
