package cia

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// dayRegions derives, for one service, the day as each witness saw it
// (CONTRACTS §7.5 for cia-run/v2): its probe's level in every slot, the
// statistics of the latency of its successful probes, the phases, the errors by
// class, the slots that needed a retry, and the uptime. A witness has a region
// when any of the day's runs names it. Failures are not latency samples.
func dayRegions(slots []*Slot, service string) map[string]record.CIADayRegion {
	names := map[string]bool{}
	for _, s := range slots {
		if _, ok := s.serviceDims(service); ok {
			for w := range s.Witnesses {
				names[w] = true
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]record.CIADayRegion, len(names))
	for w := range names {
		out[w] = dayRegion(slots, service, w)
	}
	return out
}

func dayRegion(slots []*Slot, service, witness string) record.CIADayRegion {
	letters := []byte(strings.Repeat("-", SlotsPerDay))
	slotsMs := make([]*int, len(slots))
	var phases [phaseCount][]int
	var errors record.ErrorCounts
	region := record.CIADayRegion{}
	for i, s := range slots {
		if s == nil {
			continue
		}
		p, ok := s.Probes[witness][service]
		if !ok || p.Level == record.LevelNone {
			continue
		}
		letters[i] = Letter(p.Level)
		if p.Attempts == 2 {
			region.Retries++
		}
		switch {
		case p.TotalMs != nil:
			slotsMs[i] = p.TotalMs
			for k, ms := range p.Phases {
				if ms != nil {
					phases[k] = append(phases[k], *ms)
				}
			}
		case p.Level == record.LevelFail:
			errors.Add(p.Class)
		}
		if p.Level != record.LevelFail {
			region.Uptime.Up++
		}
		region.Uptime.Measured++
	}
	region.Availability = string(letters)
	region.Latency = LatencyOf(slotsMs)
	region.Errors = errors
	region.Phases = record.PhaseSet{
		DNSMs: PhaseOf(phases[PhaseDNS]), ConnectMs: PhaseOf(phases[PhaseConnect]), TLSMs: PhaseOf(phases[PhaseTLS]),
		WaitMs: PhaseOf(phases[PhaseWait]), TransferMs: PhaseOf(phases[PhaseTransfer]),
	}
	return region
}

func (s *Slot) serviceDims(service string) (Dims, bool) {
	if s == nil {
		return Dims{}, false
	}
	d, ok := s.Services[service]
	return d, ok
}

// summaryRegions derives, for one service, the 90 days as each witness saw
// them from the regions of the day files: the day's letter from the counts of
// its availability letters, the uptime over the window, and the day's p50 and
// p95. A day without a file, or without that witness, counts as no data.
func summaryRegions(window []*record.CIADay, service string) map[string]record.CIASummaryRegion {
	names := map[string]bool{}
	for _, d := range window {
		if d != nil {
			for w := range d.Services[service].Regions {
				names[w] = true
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]record.CIASummaryRegion, len(names))
	for w := range names {
		r := record.CIASummaryRegion{P50Ms: make([]*int, len(window)), P95Ms: make([]*int, len(window))}
		days := make([]byte, len(window))
		for k, d := range window {
			days[k] = '-'
			if d == nil {
				continue
			}
			day, ok := d.Services[service].Regions[w]
			if !ok {
				continue
			}
			ok2, warn, fail := countLetters(day.Availability)
			days[k] = DayLetter("availability", ok2, warn, fail)
			r.Uptime.Up += day.Uptime.Up
			r.Uptime.Measured += day.Uptime.Measured
			r.P50Ms[k], r.P95Ms[k] = day.Latency.P50Ms, day.Latency.P95Ms
		}
		r.Days = string(days)
		out[w] = r
	}
	return out
}

func countLetters(letters string) (ok, warn, fail int) {
	return strings.Count(letters, "o"), strings.Count(letters, "w"), strings.Count(letters, "f")
}

// latestRegions derives, for one service, each witness's probe in the latest
// run: its level and code (a witness that measured nothing has level none and
// code vantage), the latency when it succeeded, and since when the level has
// held. since gives that slot.
func latestRegions(s Slot, service string, since func(witness string) string) map[string]record.CIALatestRegion {
	out := map[string]record.CIALatestRegion{}
	for _, w := range s.witnessIDs() {
		p, ok := s.Probes[w][service]
		if !ok {
			p = RegionProbe{Level: record.LevelNone, Code: "vantage"}
		}
		out[w] = record.CIALatestRegion{Level: p.Level, Code: p.Code, LatencyMs: p.TotalMs, Since: since(w)}
	}
	return out
}

// latestWitnesses derives, for the latest run, whether each witness measured.
func latestWitnesses(s Slot, since func(witness string) string) map[string]record.CIALatestWitness {
	out := map[string]record.CIALatestWitness{}
	for _, w := range s.witnessIDs() {
		st := s.Witnesses[w]
		l := record.CIALatestWitness{Status: st.Status, Since: since(w)}
		if st.Reason != "" {
			l.Reason = &st.Reason
		}
		if st.Vantage != "" {
			l.Vantage = &st.Vantage
		}
		out[w] = l
	}
	return out
}

func (s Slot) witnessIDs() []string {
	ids := make([]string, 0, len(s.Witnesses))
	for w := range s.Witnesses {
		ids = append(ids, w)
	}
	sort.Strings(ids)
	return slices.Clone(Witnesses(ids))
}

// RegionSince is Since for one witness's probe of a service: the start of the
// unbroken sequence of runs, ending at the last one of chain, in which the
// probe had the level it has in the last run (none when the witness is named
// but measured nothing). A run that does not name the witness breaks it.
func RegionSince(chain []Slot, service, witness string) (since time.Time, reachedStart bool) {
	return sequenceStart(chain, func(s Slot) (string, bool) {
		if _, listed := s.Witnesses[witness]; !listed {
			return "", false
		}
		if _, hasService := s.Services[service]; !hasService {
			return "", false
		}
		if p, ok := s.Probes[witness][service]; ok {
			return p.Level, true
		}
		return record.LevelNone, true
	})
}

// WitnessSince is Since for a witness: the start of the unbroken sequence of
// runs, ending at the last one of chain, in which it had the status it has in
// the last run. A run that does not name the witness breaks it.
func WitnessSince(chain []Slot, witness string) (since time.Time, reachedStart bool) {
	return sequenceStart(chain, func(s Slot) (string, bool) {
		st, ok := s.Witnesses[witness]
		return st.Status, ok
	})
}

// sequenceStart walks back from the last slot while state gives the same value
// as there; ok false ends the sequence.
func sequenceStart(chain []Slot, state func(Slot) (string, bool)) (time.Time, bool) {
	last := len(chain) - 1
	want, _ := state(chain[last])
	start := last
	for start > 0 {
		if got, ok := state(chain[start-1]); !ok || got != want {
			return chain[start].Time, false
		}
		start--
	}
	return chain[0].Time, true
}
