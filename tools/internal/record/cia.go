package record

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Levels, from the worst to the least informative. A dimension's level is the
// worst of its checks; "none" means not measured.
const (
	LevelOK   = "ok"
	LevelWarn = "warn"
	LevelFail = "fail"
	LevelNone = "none"
)

// Dimensions lists the three audited properties in the order every file uses.
var Dimensions = [3]string{"availability", "integrity", "confidentiality"}

// CIARun is a cia-run/v1 record: what one auditor run measured in one slot.
type CIARun struct {
	Schema     string `json:"schema"`
	Slot       string `json:"slot"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	Prev       *Link  `json:"prev"`
	// Vantage is where the probes ran, as provider:region. Optional.
	Vantage string `json:"vantage,omitempty"`
	// Control is the control probe of the run. Optional.
	Control   *CIAControl           `json:"control,omitempty"`
	Incidents CIARunIncidents       `json:"incidents"`
	Services  map[string]CIAService `json:"services"`
}

// CIAControl is the control probe: a request to a host outside diagnos, made
// together with the service probes.
type CIAControl struct {
	Host       string `json:"host"`
	OK         bool   `json:"ok"`
	HTTPStatus *int   `json:"httpStatus"`
	LatencyMs  *int   `json:"latencyMs"`
}

// CIARunIncidents says where a run read the declared incidents from.
type CIARunIncidents struct {
	Source   string  `json:"source"`
	Commit   *string `json:"commit"`
	ReadAt   *string `json:"readAt"`
	Snapshot *Link   `json:"snapshot"`
}

// CIAService is one service in a run record.
type CIAService struct {
	URL             string       `json:"url"`
	Availability    CIADimension `json:"availability"`
	Integrity       CIADimension `json:"integrity"`
	Confidentiality CIADimension `json:"confidentiality"`
}

// Dimension returns the named dimension of the service.
func (s CIAService) Dimension(name string) CIADimension {
	switch name {
	case "availability":
		return s.Availability
	case "integrity":
		return s.Integrity
	}
	return s.Confidentiality
}

// CIADimension is the level of one dimension and the checks behind it.
type CIADimension struct {
	Level  string     `json:"level"`
	Checks []CIACheck `json:"checks"`
}

// CIACheck is the union of the check kinds of a run record. Exactly one of
// its fields is set; (un)marshalling dispatches on the check's id.
type CIACheck struct {
	Healthz    *HealthzCheck
	Checkpoint *CheckpointCheck
	Release    *ReleaseCheck
	Log        *LogCheck
	Incidents  *IncidentsCheck
}

// ID, Level and Code are the three fields every kind of check has.
func (c CIACheck) ID() string {
	switch {
	case c.Healthz != nil:
		return c.Healthz.ID
	case c.Checkpoint != nil:
		return c.Checkpoint.ID
	case c.Release != nil:
		return c.Release.ID
	case c.Log != nil:
		return c.Log.ID
	case c.Incidents != nil:
		return c.Incidents.ID
	}
	return ""
}

func (c CIACheck) Level() string {
	switch {
	case c.Healthz != nil:
		return c.Healthz.Level
	case c.Checkpoint != nil:
		return c.Checkpoint.Level
	case c.Release != nil:
		return c.Release.Level
	case c.Log != nil:
		return c.Log.Level
	case c.Incidents != nil:
		return c.Incidents.Level
	}
	return ""
}

func (c CIACheck) Code() string {
	switch {
	case c.Healthz != nil:
		return c.Healthz.Code
	case c.Checkpoint != nil:
		return c.Checkpoint.Code
	case c.Release != nil:
		return c.Release.Code
	case c.Log != nil:
		return c.Log.Code
	case c.Incidents != nil:
		return c.Incidents.Code
	}
	return ""
}

// MarshalJSON writes the check that is set.
func (c CIACheck) MarshalJSON() ([]byte, error) {
	switch {
	case c.Healthz != nil:
		return json.Marshal(c.Healthz)
	case c.Checkpoint != nil:
		return json.Marshal(c.Checkpoint)
	case c.Release != nil:
		return json.Marshal(c.Release)
	case c.Log != nil:
		return json.Marshal(c.Log)
	case c.Incidents != nil:
		return json.Marshal(c.Incidents)
	}
	return nil, fmt.Errorf("empty check")
}

// UnmarshalJSON picks the check kind from its id and decodes it strictly.
func (c *CIACheck) UnmarshalJSON(data []byte) error {
	var head struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	switch {
	case head.ID == "healthz":
		c.Healthz = new(HealthzCheck)
		return dec.Decode(c.Healthz)
	case head.ID == "release":
		c.Release = new(ReleaseCheck)
		return dec.Decode(c.Release)
	case head.ID == "incidents":
		c.Incidents = new(IncidentsCheck)
		return dec.Decode(c.Incidents)
	case len(head.ID) > 11 && head.ID[:11] == "checkpoint:":
		c.Checkpoint = new(CheckpointCheck)
		return dec.Decode(c.Checkpoint)
	case len(head.ID) > 4 && head.ID[:4] == "log:":
		c.Log = new(LogCheck)
		return dec.Decode(c.Log)
	}
	return fmt.Errorf("unknown check id %q", head.ID)
}

// HealthzCheck is GET <url>healthz.
type HealthzCheck struct {
	ID          string  `json:"id"`
	Level       string  `json:"level"`
	Code        string  `json:"code"`
	Attempts    int     `json:"attempts"`
	HTTPStatus  *int    `json:"httpStatus"`
	LatencyMs   *int    `json:"latencyMs"`
	TLSNotAfter *string `json:"tlsNotAfter"`
	// Timings says where the time of the deciding attempt went. Optional: it
	// is left out of records written before it existed.
	Timings *Timings `json:"timings,omitempty"`
	Error   *string  `json:"error"`
}

// Timings is the HTTP client's own trace of one attempt, in whole
// milliseconds. A phase that did not happen or did not finish is nil.
type Timings struct {
	DNSMs       *int `json:"dnsMs"`
	ConnectMs   *int `json:"connectMs"`
	TLSMs       *int `json:"tlsMs"`
	FirstByteMs *int `json:"firstByteMs"`
	TotalMs     int  `json:"totalMs"`
}

// CheckpointCheck is whether a log's checkpoint could be read.
type CheckpointCheck struct {
	ID    string  `json:"id"`
	Level string  `json:"level"`
	Code  string  `json:"code"`
	Error *string `json:"error"`
}

// ReleaseCheck is the integrity verdict for the release a service reports.
type ReleaseCheck struct {
	ID        string        `json:"id"`
	Level     string        `json:"level"`
	Code      string        `json:"code"`
	Version   *string       `json:"version"`
	Commit    *string       `json:"commit"`
	Digest    *string       `json:"digest"`
	Verdict   *string       `json:"verdict"`
	FirstSeen *string       `json:"firstSeen"`
	Served    *ServedSample `json:"served"`
	Error     *string       `json:"error"`
}

// ServedSample is the progress of sampling the files a service serves.
type ServedSample struct {
	Checked       int     `json:"checked"`
	Total         int     `json:"total"`
	Mismatches    int     `json:"mismatches"`
	LastCheckedAt *string `json:"lastCheckedAt"`
}

// LogCheck is what the witness did with a log in this run.
type LogCheck struct {
	ID      string  `json:"id"`
	Level   string  `json:"level"`
	Code    string  `json:"code"`
	Status  string  `json:"status"`
	Size    *uint64 `json:"size"`
	Record  *string `json:"record"`
	Finding *string `json:"finding"`
	Error   *string `json:"error"`
}

// IncidentsCheck lists the declared incidents affecting a service.
type IncidentsCheck struct {
	ID    string   `json:"id"`
	Level string   `json:"level"`
	Code  string   `json:"code"`
	Open  []string `json:"open"`
	Error *string  `json:"error"`
}
