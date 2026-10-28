package record

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CIARunV2 is a cia-run/v2 record: what one run measured in one slot, from
// every witness. The raw measurements are in Witnesses, each signed by its
// witness; Services holds the combined verdicts, which anyone can recompute
// from them. It lives at the same path and in the same chain as cia-run/v1.
type CIARunV2 struct {
	Schema     string                  `json:"schema"`
	Slot       string                  `json:"slot"`
	StartedAt  string                  `json:"startedAt"`
	FinishedAt string                  `json:"finishedAt"`
	Prev       *Link                   `json:"prev"`
	Incidents  CIARunIncidents         `json:"incidents"`
	Witnesses  map[string]WitnessEntry `json:"witnesses"`
	Services   map[string]CIAServiceV2 `json:"services"`
}

// CIAServiceV2 is one service of a cia-run/v2 record.
type CIAServiceV2 struct {
	URL             string         `json:"url"`
	Availability    CIADimensionV2 `json:"availability"`
	Integrity       CIADimensionV2 `json:"integrity"`
	Confidentiality CIADimensionV2 `json:"confidentiality"`
}

// CIADimensionV2 is the combined level of a dimension and the checks behind it.
type CIADimensionV2 struct {
	Level  string       `json:"level"`
	Checks []CIACheckV2 `json:"checks"`
}

// CIACheckV2 is the union of the check kinds of a cia-run/v2 record. The
// healthz and checkpoint checks are combined verdicts and the log check names
// the finding; release and incidents checks are the v1 ones.
type CIACheckV2 struct {
	Healthz    *CombinedCheck
	Checkpoint *CombinedCheck
	Release    *ReleaseCheck
	Log        *CombinedLog
	Incidents  *IncidentsCheck
}

// CombinedCheck is a reachability check combined over the measuring witnesses.
type CombinedCheck struct {
	ID    string  `json:"id"`
	Level string  `json:"level"`
	Code  string  `json:"code"`
	Error *string `json:"error"`
}

// CombinedLog is the evidence check on a log: the worst witness's verdict.
type CombinedLog struct {
	ID      string  `json:"id"`
	Level   string  `json:"level"`
	Code    string  `json:"code"`
	Finding *string `json:"finding"`
	Error   *string `json:"error"`
}

// Level is the level of the check that is set.
func (c CIACheckV2) Level() string {
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

// MarshalJSON writes the check that is set.
func (c CIACheckV2) MarshalJSON() ([]byte, error) {
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
func (c *CIACheckV2) UnmarshalJSON(data []byte) error {
	var head struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return err
	}
	switch {
	case head.ID == "healthz":
		c.Healthz = new(CombinedCheck)
		return strictUnmarshal(data, c.Healthz)
	case head.ID == "release":
		c.Release = new(ReleaseCheck)
		return strictUnmarshal(data, c.Release)
	case head.ID == "incidents":
		c.Incidents = new(IncidentsCheck)
		return strictUnmarshal(data, c.Incidents)
	case strings.HasPrefix(head.ID, "checkpoint:") && len(head.ID) > len("checkpoint:"):
		c.Checkpoint = new(CombinedCheck)
		return strictUnmarshal(data, c.Checkpoint)
	case strings.HasPrefix(head.ID, "log:") && len(head.ID) > len("log:"):
		c.Log = new(CombinedLog)
		return strictUnmarshal(data, c.Log)
	}
	return fmt.Errorf("unknown check id %q", head.ID)
}

// DecodeRun parses a run record of either version, strictly, and returns it as
// the derivations read it. A cia-run/v2 record is projected (see AsRun); the
// record itself is in the V2 field.
func DecodeRun(data []byte) (*CIARun, error) {
	var tag struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &tag); err != nil {
		return nil, err
	}
	switch tag.Schema {
	case "cia-run/v1":
		var r CIARun
		if err := Decode(data, tag.Schema, &r); err != nil {
			return nil, err
		}
		return &r, nil
	case "cia-run/v2":
		var r CIARunV2
		if err := Decode(data, tag.Schema, &r); err != nil {
			return nil, err
		}
		return r.AsRun(), nil
	}
	return nil, fmt.Errorf("schema is %q, want cia-run/v1 or cia-run/v2", tag.Schema)
}

// AsRun projects the record onto the shape the derivations read: the combined
// verdicts of every service, which are the same kind of fact in both versions.
// What differs in kind moves with it only as far as the views need it: the
// healthz check carries the primary witness's latency, which is what the day
// files, the summary and the latest view have always reported as the service's
// latency. The per-witness detail stays in V2.
func (r *CIARunV2) AsRun() *CIARun {
	out := &CIARun{Schema: r.Schema, Slot: r.Slot, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, Prev: r.Prev,
		Incidents: r.Incidents, Services: make(map[string]CIAService, len(r.Services)), V2: r}
	for id, svc := range r.Services {
		out.Services[id] = CIAService{URL: svc.URL,
			Availability:    r.projectDimension(id, svc.Availability),
			Integrity:       r.projectDimension(id, svc.Integrity),
			Confidentiality: r.projectDimension(id, svc.Confidentiality),
		}
	}
	return out
}

func (r *CIARunV2) projectDimension(service string, d CIADimensionV2) CIADimension {
	out := CIADimension{Level: d.Level, Checks: make([]CIACheck, len(d.Checks))}
	for i, c := range d.Checks {
		switch {
		case c.Healthz != nil:
			h := &HealthzCheck{ID: c.Healthz.ID, Level: c.Healthz.Level, Code: c.Healthz.Code, Error: c.Healthz.Error}
			h.LatencyMs = r.PrimaryLatency(service)
			out.Checks[i].Healthz = h
		case c.Checkpoint != nil:
			out.Checks[i].Checkpoint = &CheckpointCheck{ID: c.Checkpoint.ID, Level: c.Checkpoint.Level, Code: c.Checkpoint.Code, Error: c.Checkpoint.Error}
		case c.Release != nil:
			out.Checks[i].Release = c.Release
		case c.Log != nil:
			out.Checks[i].Log = &LogCheck{ID: c.Log.ID, Level: c.Log.Level, Code: c.Log.Code, Finding: c.Log.Finding, Error: c.Log.Error}
		case c.Incidents != nil:
			out.Checks[i].Incidents = c.Incidents
		}
	}
	return out
}

// PrimaryLatency is the time the primary witness's probe of the service took,
// nil when the witness did not measure it or the probe failed: the latency the
// views report for the service.
func (r *CIARunV2) PrimaryLatency(service string) *int {
	w, ok := r.Witnesses[WitnessEurope]
	if !ok || w.Measured == nil {
		return nil
	}
	p, ok := w.Measured.Probes[service]
	if !ok || !Succeeded(p.Code) || p.Timings == nil {
		return nil
	}
	ms := p.Timings.TotalMs
	return &ms
}

// Succeeded says a probe code is an answer the check accepts: ok, retried,
// slow and tls-expiring. Only such probes are latency samples.
func Succeeded(code string) bool {
	switch code {
	case "ok", "retried", "slow", "tls-expiring":
		return true
	}
	return false
}
