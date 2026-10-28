package cia

import (
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

func ip(v int) *int { return &v }

// A v1 check says how it failed only through its code and status; the class and
// the phases of the primary witness's probe follow from them.
func TestProbeOfV1(t *testing.T) {
	status := func(n int) *int { return &n }
	for _, c := range []struct {
		name  string
		h     record.HealthzCheck
		level string
		class string
		total *int
		wait  *int
		xfer  *int
	}{
		{"answer", record.HealthzCheck{Level: "ok", Code: "ok", Attempts: 1, LatencyMs: ip(100),
			Timings: &record.Timings{DNSMs: ip(4), ConnectMs: ip(6), TLSMs: ip(10), FirstByteMs: ip(60), TotalMs: 100}}, "ok", "", ip(100), ip(40), ip(40)},
		{"first byte before the phases add up: the wait cannot be negative", record.HealthzCheck{Level: "ok", Code: "ok", Attempts: 1, LatencyMs: ip(10),
			Timings: &record.Timings{DNSMs: ip(4), ConnectMs: ip(6), TLSMs: ip(10), FirstByteMs: ip(8), TotalMs: 10}}, "ok", "", ip(10), ip(0), ip(2)},
		{"answer without timings", record.HealthzCheck{Level: "ok", Code: "slow", Attempts: 1, LatencyMs: ip(1200)}, "ok", "", ip(1200), nil, nil},
		{"timeout", record.HealthzCheck{Level: "fail", Code: "timeout", Attempts: 2}, "fail", "timeout", nil, nil, nil},
		{"connection refused, which v1 counted as one class with a failed lookup", record.HealthzCheck{Level: "fail", Code: "connect-error", Attempts: 2}, "fail", "connect", nil, nil, nil},
		{"handshake", record.HealthzCheck{Level: "fail", Code: "tls-error", Attempts: 2}, "fail", "tls", nil, nil, nil},
		{"503", record.HealthzCheck{Level: "fail", Code: "http-status", Attempts: 2, HTTPStatus: status(503)}, "fail", "http-5xx", nil, nil, nil},
		{"404", record.HealthzCheck{Level: "fail", Code: "http-status", Attempts: 2, HTTPStatus: status(404)}, "fail", "http-4xx", nil, nil, nil},
		{"a status that is neither", record.HealthzCheck{Level: "fail", Code: "http-status", Attempts: 2, HTTPStatus: status(302)}, "fail", "assertion", nil, nil, nil},
		{"a body that broke the contract", record.HealthzCheck{Level: "fail", Code: "invalid-body", Attempts: 1}, "fail", "assertion", nil, nil, nil},
		{"not measured", record.HealthzCheck{Level: "none", Code: "vantage", Attempts: 2}, "none", "", nil, nil, nil},
	} {
		p := probeOfV1(&c.h)
		if p.Level != c.level || p.Class != c.class || val(p.TotalMs) != val(c.total) ||
			val(p.Phases[PhaseWait]) != val(c.wait) || val(p.Phases[PhaseTransfer]) != val(c.xfer) {
			t.Errorf("%s: %+v, want level %s class %q total %v wait %v transfer %v", c.name, p, c.level, c.class, val(c.total), val(c.wait), val(c.xfer))
		}
	}
}

func TestProbeOfV2UsesTheClassTheProbeStates(t *testing.T) {
	class := "connect"
	p := probeOfV2(record.Probe{Code: "timeout", Class: &class, Attempts: 2, Timings: &record.ProbeTimings{TotalMs: 3004}})
	if p.Level != "fail" || p.Class != "connect" || p.TotalMs != nil {
		t.Errorf("a failed probe: %+v", p)
	}
	p = probeOfV2(record.Probe{Code: "slow", Attempts: 1, Timings: &record.ProbeTimings{DNSMs: ip(3), TotalMs: 1100}})
	if p.Level != "warn" || p.Class != "" || val(p.TotalMs) != 1100 || val(p.Phases[PhaseDNS]) != 3 || p.Phases[PhaseTLS] != nil {
		t.Errorf("a slow answer is a latency sample: %+v", p)
	}
	p = probeOfV2(record.Probe{Code: "challenged", Attempts: 1, Timings: &record.ProbeTimings{TotalMs: 70}})
	if p.Level != "none" || p.TotalMs != nil {
		t.Errorf("a challenge says nothing about the service and is no sample: %+v", p)
	}
}

func TestWitnessesOfARun(t *testing.T) {
	reason := func(s string) *string { return &s }
	v2 := &record.CIARunV2{Witnesses: map[string]record.WitnessEntry{
		"europe": {Status: "ok", Measured: &record.Measured{Vantage: "scaleway:fr-par", Probes: map[string]record.Probe{"vault": {Code: "ok", Attempts: 1, Timings: &record.ProbeTimings{TotalMs: 80}}}}},
		"latam":  {Status: "unavailable", Reason: reason("timeout")},
		"asia":   {Status: "unavailable", Reason: reason("off")},
	}}
	states, probes := witnessesOf(&record.CIARun{V2: v2})
	if states["europe"].Vantage != "scaleway:fr-par" || states["latam"] != (WitnessState{Status: "unavailable", Reason: "timeout"}) {
		t.Errorf("states %+v", states)
	}
	if _, listed := states["asia"]; listed {
		t.Error("a witness that is off is listed")
	}
	if val(probes["europe"]["vault"].TotalMs) != 80 || len(probes["latam"]) != 0 {
		t.Errorf("probes %+v", probes)
	}
	states, probes = witnessesOf(&record.CIARun{Vantage: "scaleway:fr-par"})
	if len(states) != 1 || states["europe"].Status != "ok" || probes["europe"] == nil {
		t.Errorf("a v1 record is the primary witness's alone: %+v %+v", states, probes)
	}
}
