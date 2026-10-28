package main

import (
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// vantagePoint is where a witness measures from: the place and the addresses
// the examples give it. Documentation prefixes only (RFC 5737).
type vantagePoint struct {
	vantage string
	edge    string
	ip      map[string]string
	lagMs   int // how much later its answers arrive than the primary's, on average
}

var vantagePoints = map[string]vantagePoint{
	record.WitnessEurope: {"scaleway:fr-par", "CDG", map[string]string{"frontend": "192.0.2.10", "sign": "192.0.2.20", "vault": "192.0.2.30", "status": "198.51.100.40"}, 0},
	record.WitnessLatam:  {"oci:sa-saopaulo-1", "GRU", map[string]string{"frontend": "203.0.113.10", "sign": "203.0.113.20", "vault": "203.0.113.30", "status": "203.0.113.40"}, 6},
}

var (
	issuers = map[string]string{"frontend": "WE1", "sign": "WE1", "vault": "WE1", "status": "R11"}
	sizes   = map[string]int{"frontend": 342, "sign": 356, "vault": 349, "status": 371}
)

// probeFor is what a witness saw of a service in a slot when the scenario says
// the result is code. The numbers of the primary witness are the ones the
// single-vantage history always had, split into the phases of the new record;
// the other witness's are the same service seen from further away.
func probeFor(witness, service string, slot time.Time, code string) record.Probe {
	vp := vantagePoints[witness]
	p := record.Probe{Code: code, Attempts: 1, IP: ptr(vp.ip[service])}
	switch code {
	case "vantage":
		// The witness's own network failed: nothing was measured, apart from the time it took to give up.
		p.Attempts, p.IP = 2, nil
		p.Timings = &record.ProbeTimings{TotalMs: 7960 + jitter(service+" total "+witness, slot, 40)}
		p.Error = ptr(vantageText)
		return p
	case "challenged":
		p.HTTPStatus, p.HTTPVersion, p.TLSVersion, p.TLSNotAfter, p.TLSIssuer, p.Edge, p.Bytes = ptr(403), ptr("2"), ptr("1.3"),
			ptr("2027-01-14T23:59:59Z"), ptr(issuers[service]), ptr(vp.edge), ptr(1203)
		p.Timings = v2Timings(phases(service+" "+witness, slot, 60+jitter(service+" challenged", slot, 30), false))
		p.Error = ptr("The edge answered with a bot challenge, not with the service: nothing was learned about the service.")
		return p
	case "timeout":
		if witness == record.WitnessLatam {
			p.Attempts, p.Class, p.RetriedAfter, p.IP = 2, ptr("connect"), ptr("connect"), ptr(vp.ip[service])
			p.Timings = &record.ProbeTimings{DNSMs: ptr(3 + jitter(service+" dns latam", slot, 4)), TotalMs: 3000 + jitter(service+" total latam", slot, 8)}
			p.Error = ptr("No TCP connection within 3 s, twice.")
			return p
		}
	}
	h := healthzCheck(service, slot, code).Healthz
	p.Attempts, p.HTTPStatus, p.Error = h.Attempts, h.HTTPStatus, h.Error
	t := h.Timings
	if vp.lagMs > 0 && h.LatencyMs != nil {
		total := *h.LatencyMs + vp.lagMs + jitter(service+" lag "+witness, slot, max(8, *h.LatencyMs/4))
		t = phases(service+" "+witness, slot, total, code == "slow")
	}
	p.Timings = v2Timings(t)
	if t.TLSMs != nil {
		p.HTTPVersion, p.TLSVersion, p.TLSNotAfter, p.TLSIssuer, p.Edge = ptr("2"), ptr("1.3"), ptr("2027-01-14T23:59:59Z"), ptr(issuers[service]), ptr(vp.edge)
		p.Bytes = ptr(sizes[service])
	}
	switch code {
	case "retried":
		p.RetriedAfter = ptr("timeout")
	case "http-status":
		p.Class, p.RetriedAfter, p.Bytes = ptr("http-5xx"), ptr("http-5xx"), ptr(118)
	case "connect-error":
		p.Class, p.RetriedAfter = ptr("connect"), ptr("connect")
	case "timeout":
		p.Class, p.RetriedAfter = ptr("timeout"), ptr("timeout")
	}
	return p
}

// v2Timings splits the timings of the single-vantage history into the phases of
// the new record. firstByteMs ran from the start of the attempt there, so the
// wait is what is left of it after the three phases before it, and the transfer
// is what follows it.
func v2Timings(t *record.Timings) *record.ProbeTimings {
	out := &record.ProbeTimings{DNSMs: t.DNSMs, ConnectMs: t.ConnectMs, TLSMs: t.TLSMs, TotalMs: t.TotalMs}
	if t.FirstByteMs != nil {
		before := orZero(t.DNSMs) + orZero(t.ConnectMs) + orZero(t.TLSMs)
		wait, transfer := max(0, *t.FirstByteMs-before), t.TotalMs-*t.FirstByteMs
		out.WaitMs, out.TransferMs = &wait, &transfer
	}
	return out
}

func orZero(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
