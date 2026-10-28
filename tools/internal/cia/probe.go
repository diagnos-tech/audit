package cia

import (
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// Phases of a probe, in the order RegionProbe.Phases has them.
const (
	PhaseDNS = iota
	PhaseConnect
	PhaseTLS
	PhaseWait
	PhaseTransfer
	phaseCount
)

// WitnessState is whether a witness measured in a run, and from where.
type WitnessState struct {
	Status  string // ok or unavailable
	Reason  string // why it is unavailable, "" when it is not
	Vantage string // where it measured from, "" when it did not
}

// RegionProbe is what one witness saw of one service in one run, reduced to
// what the views report.
type RegionProbe struct {
	Level string
	Code  string
	// Class is the error class of a failed probe, "" otherwise.
	Class    string
	Attempts int
	// TotalMs and Phases are set when the probe succeeded; a phase that did
	// not happen is nil.
	TotalMs *int
	Phases  [phaseCount]*int
}

// witnessesOf lists the witnesses of a run and what each saw. A witness whose
// entry says it is off is not configured, and is not listed at all.
func witnessesOf(r *record.CIARun) (map[string]WitnessState, map[string]map[string]RegionProbe) {
	states := map[string]WitnessState{}
	probes := map[string]map[string]RegionProbe{}
	if r.V2 == nil {
		states[record.WitnessEurope] = WitnessState{Status: "ok", Vantage: r.Vantage}
		probes[record.WitnessEurope] = map[string]RegionProbe{}
		for id, svc := range r.Services {
			for _, c := range svc.Availability.Checks {
				if c.Healthz != nil {
					probes[record.WitnessEurope][id] = probeOfV1(c.Healthz)
				}
			}
		}
		return states, probes
	}
	for id, e := range r.V2.Witnesses {
		if e.Status != "ok" || e.Measured == nil {
			if e.Reason == nil || *e.Reason != record.ReasonOff {
				states[id] = WitnessState{Status: "unavailable", Reason: deref(e.Reason)}
				probes[id] = map[string]RegionProbe{}
			}
			continue
		}
		states[id] = WitnessState{Status: "ok", Vantage: e.Measured.Vantage}
		probes[id] = map[string]RegionProbe{}
		for service, p := range e.Measured.Probes {
			probes[id][service] = probeOfV2(p)
		}
	}
	return states, probes
}

func probeOfV2(p record.Probe) RegionProbe {
	level, _ := LevelOfCodeV2("healthz", p.Code)
	out := RegionProbe{Level: level, Code: p.Code, Attempts: p.Attempts}
	switch {
	case record.Succeeded(p.Code) && p.Timings != nil:
		t := p.Timings
		out.TotalMs = &t.TotalMs
		out.Phases = [phaseCount]*int{t.DNSMs, t.ConnectMs, t.TLSMs, t.WaitMs, t.TransferMs}
	case level == record.LevelFail:
		out.Class = deref(p.Class)
	}
	return out
}

// probeOfV1 reads the single vantage point of a v1 record as the primary
// witness's probe. A v1 check does not say in which phase it failed beyond its
// code, so its class follows the code and the status; v1 counted a failed name
// lookup as a connection error. firstByteMs ran from the start of the attempt,
// so the wait is what is left of it after the three phases before it, and the
// transfer is what follows it.
func probeOfV1(h *record.HealthzCheck) RegionProbe {
	out := RegionProbe{Level: h.Level, Code: h.Code, Attempts: h.Attempts}
	switch {
	case record.Succeeded(h.Code):
		out.TotalMs = h.LatencyMs
		if t := h.Timings; t != nil {
			out.Phases[PhaseDNS], out.Phases[PhaseConnect], out.Phases[PhaseTLS] = t.DNSMs, t.ConnectMs, t.TLSMs
			if t.FirstByteMs != nil {
				before := valueOr0(t.DNSMs) + valueOr0(t.ConnectMs) + valueOr0(t.TLSMs)
				wait, transfer := max(0, *t.FirstByteMs-before), t.TotalMs-*t.FirstByteMs
				out.Phases[PhaseWait], out.Phases[PhaseTransfer] = &wait, &transfer
			}
		}
	case h.Level == record.LevelFail:
		out.Class = classOfV1(h)
	}
	return out
}

func classOfV1(h *record.HealthzCheck) string {
	switch h.Code {
	case "timeout":
		return "timeout"
	case "connect-error":
		return "connect"
	case "tls-error":
		return "tls"
	case "http-status":
		switch status := valueOr0(h.HTTPStatus); {
		case status >= 500:
			return "http-5xx"
		case status >= 400 && status < 500:
			return "http-4xx"
		}
	}
	return "assertion"
}

func valueOr0(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
