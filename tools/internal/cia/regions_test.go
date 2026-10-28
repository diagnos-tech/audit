package cia

import (
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// seen is a slot of the service "vault" in which the witnesses saw what the
// codes say; each probe that succeeded took 100 ms, in phases of 10, 20, 30 and
// 40 ms after the 0 ms of the lookup.
func seen(i int, probes map[string]string) *Slot {
	s := &Slot{Time: at(i), Services: map[string]Dims{"vault": {}}, Latency: map[string]int{},
		Witnesses: map[string]WitnessState{}, Probes: map[string]map[string]RegionProbe{}}
	for w, code := range probes {
		s.Witnesses[w] = WitnessState{Status: "ok"}
		level, _ := LevelOfCodeV2("healthz", code)
		p := RegionProbe{Level: level, Code: code, Attempts: 1}
		switch {
		case record.Succeeded(code):
			p.TotalMs = ip(100 + 10*i)
			p.Phases = [phaseCount]*int{ip(0), ip(10), ip(20), ip(30), ip(40)}
		case level == record.LevelFail:
			p.Class = "timeout"
			p.Attempts = 2
		}
		s.Probes[w] = map[string]RegionProbe{"vault": p}
	}
	return s
}

func TestDayRegionsHaveEachWitnessSideBySide(t *testing.T) {
	slots := make([]*Slot, SlotsPerDay)
	slots[0] = seen(0, map[string]string{"europe": "ok", "latam": "ok"})
	slots[1] = seen(1, map[string]string{"europe": "ok", "latam": "timeout"}) // regional
	slots[2] = seen(2, map[string]string{"europe": "retried", "latam": "challenged"})
	slots[3] = seen(3, map[string]string{"europe": "slow"}) // Latin America is not in this run
	r := dayRegions(slots, "vault")
	if len(r) != 2 {
		t.Fatalf("regions %v", r)
	}
	europe, latam := r["europe"], r["latam"]
	if got := europe.Availability[:5]; got != "ooow-" {
		t.Errorf("europe letters %q", got)
	}
	if got := latam.Availability[:5]; got != "of---" {
		t.Errorf("latam letters %q: a failure is red in its own region, a challenge and an absence are grey", got)
	}
	if europe.Latency.Samples != 4 || latam.Latency.Samples != 1 {
		t.Errorf("samples %d and %d: only probes that succeeded are latency samples", europe.Latency.Samples, latam.Latency.Samples)
	}
	if latam.Errors.Timeout != 1 || latam.Errors.Total() != 1 || europe.Errors.Total() != 0 {
		t.Errorf("errors %+v and %+v", latam.Errors, europe.Errors)
	}
	if europe.Uptime != (record.CIAUptime{Up: 4, Measured: 4}) || latam.Uptime != (record.CIAUptime{Up: 1, Measured: 2}) {
		t.Errorf("uptime %+v and %+v", europe.Uptime, latam.Uptime)
	}
	if latam.Retries != 1 || europe.Retries != 0 {
		t.Errorf("retries %d and %d: a failed probe needed its second attempt", latam.Retries, europe.Retries)
	}
	if val(europe.Phases.DNSMs.MeanMs) != 0 || val(europe.Phases.TransferMs.P95Ms) != 40 {
		t.Errorf("phases %+v", europe.Phases)
	}
	if val(europe.Latency.P50Ms) != 110 || val(europe.Latency.MinMs) != 100 || val(europe.Latency.MaxMs) != 130 {
		t.Errorf("europe latency %+v", europe.Latency)
	}
}

func TestDayRegionsAreAbsentWithoutWitnesses(t *testing.T) {
	if r := dayRegions(make([]*Slot, SlotsPerDay), "vault"); r != nil {
		t.Errorf("a day without a run has regions: %v", r)
	}
}

// The summary copies the days of each witness: the letter from the counts of
// its availability letters, the uptime, and the median and p95 of the day.
func TestSummaryRegions(t *testing.T) {
	day := func(avail string, p50 int) *record.CIADay {
		region := record.CIADayRegion{Availability: avail, Uptime: record.CIAUptime{Up: strings.Count(avail, "o") + strings.Count(avail, "w"), Measured: len(avail) - strings.Count(avail, "-")}}
		region.Latency.P50Ms, region.Latency.P95Ms = &p50, &p50
		return &record.CIADay{Services: map[string]record.CIADayLetters{"vault": {Regions: map[string]record.CIADayRegion{"latam": region}}}}
	}
	window := make([]*record.CIADay, WindowDays)
	window[88] = day("ooooffff", 120)
	window[89] = day("oow-----", 130)
	r := summaryRegions(window, "vault")["latam"]
	if r.Days[87:] != "-fw" {
		t.Errorf("days %q: four failed slots make a red day, a warn slot an amber one, a missing day grey", r.Days[85:])
	}
	if r.Uptime != (record.CIAUptime{Up: 7, Measured: 11}) {
		t.Errorf("uptime %+v", r.Uptime)
	}
	if val(r.P50Ms[88]) != 120 || r.P50Ms[87] != nil || val(r.P95Ms[89]) != 130 || len(r.P50Ms) != WindowDays {
		t.Errorf("p50 %v", r.P50Ms[85:])
	}
	if summaryRegions(window[:80], "vault") != nil {
		t.Error("regions out of nothing")
	}
}

func TestRegionAndWitnessSince(t *testing.T) {
	mk := func(i int, latam string) Slot {
		s := seen(i, map[string]string{"europe": "ok"})
		if latam != "" {
			s.Witnesses["latam"] = WitnessState{Status: map[bool]string{true: "ok", false: "unavailable"}[latam != "gone"]}
			if latam != "gone" {
				level, _ := LevelOfCodeV2("healthz", latam)
				s.Probes["latam"] = map[string]RegionProbe{"vault": {Level: level, Code: latam}}
			}
		}
		return *s
	}
	chain := []Slot{mk(0, ""), mk(1, "ok"), mk(2, "ok"), mk(3, "timeout"), mk(4, "timeout")}
	if since, reached := RegionSince(chain, "vault", "latam"); !since.Equal(at(3)) || reached {
		t.Errorf("the failure began at slot 3: %v %v", since, reached)
	}
	if since, reached := RegionSince(chain[:3], "vault", "latam"); !since.Equal(at(1)) || reached {
		t.Errorf("a run that does not name the witness breaks the sequence: %v %v", since, reached)
	}
	if since, reached := RegionSince(chain, "vault", "europe"); !since.Equal(at(0)) || !reached {
		t.Errorf("europe was ok since the start: %v %v", since, reached)
	}
	gone := []Slot{mk(0, "ok"), mk(1, "ok"), mk(2, "gone"), mk(3, "gone")}
	if since, _ := WitnessSince(gone, "latam"); !since.Equal(at(2)) {
		t.Errorf("unavailable since %v", since)
	}
	if since, reached := RegionSince(gone, "vault", "latam"); !since.Equal(at(2)) || reached {
		t.Errorf("a witness that is named but measured nothing has level none: %v %v", since, reached)
	}
}

func TestLatestRegionsOfAWitnessThatMeasuredNothing(t *testing.T) {
	s := *seen(5, map[string]string{"europe": "ok"})
	s.Witnesses["latam"] = WitnessState{Status: "unavailable", Reason: "timeout"}
	r := latestRegions(s, "vault", func(string) string { return "2026-10-01T00:00:00Z" })
	if r["latam"].Level != "none" || r["latam"].Code != "vantage" || r["latam"].LatencyMs != nil || val(r["europe"].LatencyMs) != 150 {
		t.Errorf("%+v", r)
	}
	w := latestWitnesses(s, func(string) string { return "2026-10-01T00:00:00Z" })
	if w["latam"].Status != "unavailable" || *w["latam"].Reason != "timeout" || w["latam"].Vantage != nil || w["europe"].Reason != nil {
		t.Errorf("%+v", w)
	}
}
