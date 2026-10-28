package record

// CIADay is a cia-day/v1 view: one UTC day in five-minute slots.
type CIADay struct {
	Schema    string                   `json:"schema"`
	Day       string                   `json:"day"`
	UpdatedAt string                   `json:"updatedAt"`
	Runs      string                   `json:"runs"`
	Services  map[string]CIADayLetters `json:"services"`
	Spans     []CIASpan                `json:"spans"`
}

// CIADayLetters has one 288-letter string per dimension.
type CIADayLetters struct {
	Availability    string `json:"availability"`
	Integrity       string `json:"integrity"`
	Confidentiality string `json:"confidentiality"`
	// Latency is the service's /healthz latency over the day. Optional in the
	// schema; the day file is a view, so every day file carries it.
	Latency *CIALatency `json:"latency,omitempty"`
}

// CIALatency is the 50th and 95th percentile (nearest rank) of the latencies
// of the day's runs that have one, and how many that is. Both percentiles are
// nil when Samples is 0.
type CIALatency struct {
	P50Ms   *int `json:"p50Ms"`
	P95Ms   *int `json:"p95Ms"`
	Samples int  `json:"samples"`
	// SlotsMs is the latency of each slot of the day, nil where the slot has
	// no run record or no latency. The percentiles and Samples are computed
	// from it.
	SlotsMs []*int `json:"slotsMs,omitempty"`
}

// Dimension returns the letters of the named dimension.
func (l CIADayLetters) Dimension(name string) string {
	switch name {
	case "availability":
		return l.Availability
	case "integrity":
		return l.Integrity
	}
	return l.Confidentiality
}

// CIASpan is a maximal run of slots that share a non-ok level and code.
type CIASpan struct {
	Service   string   `json:"service"`
	Dimension string   `json:"dimension"`
	From      int      `json:"from"`
	To        int      `json:"to"`
	Level     string   `json:"level"`
	Code      string   `json:"code"`
	Incidents []string `json:"incidents"`
}

// CIASummary is a cia-summary/v1 view: the last 90 days.
type CIASummary struct {
	Schema    string                       `json:"schema"`
	UpdatedAt string                       `json:"updatedAt"`
	FirstRun  string                       `json:"firstRun"`
	From      string                       `json:"from"`
	To        string                       `json:"to"`
	Services  map[string]CIASummaryService `json:"services"`
}

// CIASummaryService is one service of the summary.
type CIASummaryService struct {
	Availability    CIASeries `json:"availability"`
	Integrity       CIASeries `json:"integrity"`
	Confidentiality CIASeries `json:"confidentiality"`
	// P95Ms is, per day, oldest first, the 95th percentile latency of that
	// day's file; nil when the day has no file or no samples.
	P95Ms  []*int    `json:"p95Ms,omitempty"`
	Uptime CIAUptime `json:"uptime"`
}

// Series returns the series of the named dimension.
func (s *CIASummaryService) Series(name string) *CIASeries {
	switch name {
	case "availability":
		return &s.Availability
	case "integrity":
		return &s.Integrity
	}
	return &s.Confidentiality
}

// CIASeries is the 90 day letters of a dimension and the counts behind them:
// per day, [ok, warn, fail, none] measured slots.
type CIASeries struct {
	Days   string   `json:"days"`
	Counts [][4]int `json:"counts"`
}

// CIAUptime is availability over the window.
type CIAUptime struct {
	Up       int `json:"up"`
	Measured int `json:"measured"`
}

// CIALatest is a cia-latest/v1 view: the headline after the latest run.
type CIALatest struct {
	Schema    string                      `json:"schema"`
	UpdatedAt string                      `json:"updatedAt"`
	Slot      string                      `json:"slot"`
	Record    string                      `json:"record"`
	FirstRun  string                      `json:"firstRun"`
	Headline  CIAHeadline                 `json:"headline"`
	Services  map[string]CIALatestService `json:"services"`
	Incidents CIALatestIncidents          `json:"incidents"`
}

// CIAHeadline is the worst level per dimension over the services.
type CIAHeadline struct {
	Availability    string `json:"availability"`
	Integrity       string `json:"integrity"`
	Confidentiality string `json:"confidentiality"`
}

// CIALatestService is one service of cia-latest/v1.
type CIALatestService struct {
	URL             string                   `json:"url"`
	Availability    CIALatestAvailability    `json:"availability"`
	Integrity       CIALatestIntegrity       `json:"integrity"`
	Confidentiality CIALatestConfidentiality `json:"confidentiality"`
}

type CIALatestAvailability struct {
	Level     string `json:"level"`
	Code      string `json:"code"`
	Since     string `json:"since"`
	LatencyMs *int   `json:"latencyMs"`
	// Incidents are the published incidents affecting the dimension and not
	// resolved, newest first.
	Incidents []string `json:"incidents"`
}

type CIALatestIntegrity struct {
	Level     string   `json:"level"`
	Code      string   `json:"code"`
	Since     string   `json:"since"`
	Version   *string  `json:"version"`
	Commit    *string  `json:"commit"`
	Digest    *string  `json:"digest"`
	Verdict   *string  `json:"verdict"`
	Incidents []string `json:"incidents"`
}

type CIALatestConfidentiality struct {
	Level     string   `json:"level"`
	Code      string   `json:"code"`
	Since     string   `json:"since"`
	Incidents []string `json:"incidents"`
}

// CIALatestIncidents lists the open incidents and the snapshot in force.
type CIALatestIncidents struct {
	Open     []string `json:"open"`
	Snapshot *string  `json:"snapshot"`
}

// Sync is a sync/v1 cursor.
type Sync struct {
	Schema   string `json:"schema"`
	Seq      int    `json:"seq"`
	Journal  string `json:"journal"`
	SyncedAt string `json:"syncedAt"`
}
