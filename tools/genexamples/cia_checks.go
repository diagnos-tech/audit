package main

import (
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

func ptr[T any](v T) *T { return &v }

// logOutcome is what the witness did with one log in a run.
type logOutcome struct {
	status  string // unchanged, witnessed, finding, halted, error (the network failed)
	size    uint64
	record  string
	finding string
}

// latencyRange is the range of /healthz latencies of a healthy service, in
// milliseconds: the Workers behind vault and sign are slower than static hosts.
var latencyRange = map[string]struct{ min, span int }{
	"frontend": {60, 90}, "vault": {80, 170}, "sign": {160, 140}, "status": {100, 100},
}

// skewed draws a latency between min and min+span that is mostly low with a
// long tail, so a day's median and 95th percentile differ the way real ones do.
func skewed(label string, slot time.Time, min, span int) int {
	u := jitter(label, slot, 1000)
	return min + u*u*u*span/1_000_000_000
}

func levelOf(check, code string) string {
	level, ok := cia.LevelOfCode(check, code)
	if !ok {
		panic("genexamples: no level for " + check + " " + code)
	}
	return level
}

func healthzCheck(service string, slot time.Time, code string) record.CIACheck {
	h := &record.HealthzCheck{ID: "healthz", Level: levelOf("healthz", code), Code: code, Attempts: 1,
		HTTPStatus: ptr(200), TLSNotAfter: ptr("2027-01-14T23:59:59Z")}
	r := latencyRange[service]
	pct := latencyPercent(service, slot)
	latency, slow := skewed(service, slot, r.min*pct/100, r.span*pct/100), false
	switch code {
	case "retried":
		h.Attempts = 2
	case "slow":
		latency, slow = 1100+jitter(service+" slow", slot, 1500), true
	case "timeout":
		h.Attempts, h.HTTPStatus, h.TLSNotAfter = 2, nil, nil
		h.Error = ptr("No answer within 8 s, twice.")
		h.Timings = &record.Timings{DNSMs: ptr(5 + jitter(service+" dns", slot, 20)), ConnectMs: ptr(6 + jitter(service+" connect", slot, 35)),
			TotalMs: 7960 + jitter(service+" total", slot, 40)}
		return record.CIACheck{Healthz: h}
	case "connect-error":
		h.Attempts, h.HTTPStatus, h.TLSNotAfter = 2, nil, nil
		h.Error = ptr("Connection refused, twice.")
		dns := 4 + jitter(service+" dns", slot, 15)
		h.Timings = &record.Timings{DNSMs: ptr(dns), TotalMs: dns + 5 + jitter(service+" total", slot, 25)}
		return record.CIACheck{Healthz: h}
	case "http-status":
		h.Attempts, h.HTTPStatus, latency = 2, ptr(503), 35+jitter(service+" 503", slot, 30)
		h.Error = ptr("The service answered 503 twice.")
	}
	h.LatencyMs, h.Timings = ptr(latency), phases(service, slot, latency, slow)
	return record.CIACheck{Healthz: h}
}

// phases splits an attempt's total into the phases of the HTTP trace: the
// name lookup, the connection, the TLS handshake and the wait for the first
// byte, which is most of a slow answer.
func phases(service string, slot time.Time, total int, slow bool) *record.Timings {
	bounds := [4][2]int{{2, 6}, {4, 10}, {8, 18}, {40, 62}} // percent of the total
	if slow {
		bounds = [4][2]int{{1, 2}, {1, 3}, {2, 4}, {80, 90}}
	}
	var ms [4]*int
	for i, name := range []string{" dns", " connect", " tls", " first byte"} {
		b := bounds[i]
		ms[i] = ptr(total * (b[0] + jitter(service+name, slot, b[1]-b[0]+1)) / 100)
	}
	return &record.Timings{DNSMs: ms[0], ConnectMs: ms[1], TLSMs: ms[2], FirstByteMs: ms[3], TotalMs: total}
}

// incidentsCheck is the confidentiality check: the declared incidents with
// category C that the snapshot in force says affect the service in the slot.
func incidentsCheck(service string, slot time.Time, snap *snapshot) record.CIACheck {
	level, ids := record.LevelOK, []string{}
	if snap != nil {
		level, ids = snap.incidents.Level(service, "confidentiality", slot)
	}
	code := map[string]string{record.LevelOK: "clear", record.LevelWarn: "incident-low", record.LevelFail: "incident-high"}[level]
	return record.CIACheck{Incidents: &record.IncidentsCheck{ID: "incidents", Level: level, Code: code, Open: ids}}
}

func logCheck(name string, o logOutcome) record.CIACheck {
	code := map[string]string{"unchanged": "ok", "witnessed": "ok", "finding": "finding", "halted": "halted", "error": "vantage"}[o.status]
	c := &record.LogCheck{ID: "log:" + name, Level: levelOf("log", code), Code: code, Status: o.status}
	if o.record != "" {
		c.Size, c.Record = ptr(o.size), ptr(o.record)
	}
	if o.finding != "" {
		c.Finding = ptr(o.finding)
	}
	if o.status == "error" {
		c.Error = ptr(vantageText)
	}
	return record.CIACheck{Log: c}
}

func checkpointCheck(name string, vantage bool) record.CIACheck {
	if vantage {
		return record.CIACheck{Checkpoint: &record.CheckpointCheck{ID: "checkpoint:" + name, Level: record.LevelNone, Code: "vantage", Error: ptr(vantageText)}}
	}
	return record.CIACheck{Checkpoint: &record.CheckpointCheck{ID: "checkpoint:" + name, Level: record.LevelOK, Code: "ok"}}
}

const vantageText = "The auditor's own network failed (the control probe failed too), so this was not measured."

// vantageHealthz is the healthz check of a run in which the auditor's own
// network failed: both attempts failed at the transport level and the check is
// recorded as not measured.
func vantageHealthz(service string, slot time.Time) record.CIACheck {
	return record.CIACheck{Healthz: &record.HealthzCheck{ID: "healthz", Level: record.LevelNone, Code: "vantage", Attempts: 2,
		Timings: &record.Timings{TotalMs: 7960 + jitter(service+" total", slot, 40)}, Error: ptr(vantageText)}}
}

func dimension(checks ...record.CIACheck) record.CIADimension {
	levels := make([]string, len(checks))
	for i, c := range checks {
		levels[i] = c.Level()
	}
	return record.CIADimension{Level: cia.Worst(levels...), Checks: checks}
}

// releaseCheck is the integrity check of a service whose release the scenario
// says is in state code.
func (c *ciaSim) releaseCheck(service string, slot, started time.Time, code string) record.CIACheck {
	rel := c.releases[service]
	r := &record.ReleaseCheck{ID: "release", Level: levelOf("release", code), Code: code}
	switch code {
	case "vantage":
		r.Error = ptr(vantageText)
	case "unreachable":
		r.Error = ptr("The service did not answer, so its release could not be checked.")
	case "unsigned":
		r.Version, r.Commit = ptr("1.0.28+client.0.42.1"), ptr(fakeHex("frontend 1.0.28"))
		r.Error = ptr("The service runs a build without published evidence.")
	case "pending":
		r.Version, r.Commit, r.Digest = ptr(rel.version), ptr(rel.commit), ptr(rel.digest)
		r.FirstSeen = ptr(record.FormatTime(started))
		r.Error = ptr("A new release was found; its verification is pending.")
	default: // verified, served-mismatch
		r.Version, r.Commit, r.Digest, r.Verdict = ptr(rel.version), ptr(rel.commit), ptr(rel.digest), ptr(rel.verdictPath())
		r.FirstSeen = ptr(record.FormatTime(rel.firstSeen))
		checked := rel.servedChecked(slot)
		r.Served = &record.ServedSample{Checked: checked, Total: rel.summary.Served, LastCheckedAt: ptr(record.FormatTime(slot.Add(-40 * time.Second)))}
		if code == "served-mismatch" {
			r.Served.Mismatches = 1
			r.Error = ptr("A served file differs from the signed release.")
		}
	}
	return record.CIACheck{Release: r}
}
