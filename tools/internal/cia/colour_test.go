package cia

import (
	"slices"
	"testing"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

func inc(id, level string, categories []string, start, end int) Incident {
	i := Incident{ID: id, Services: []string{"vault"}, Categories: categories, Level: level, Start: at(start)}
	if end >= 0 {
		e := at(end)
		i.End = &e
	}
	return i
}

func colourAt(c Colourer, dim int, slot int, m Result) Cell { return c.Cell("vault", dim, at(slot), m) }

// An incident colours the dimensions of its categories and no other.
func TestIncidentsColourOnlyTheirCategories(t *testing.T) {
	c := Colourer{Incidents: Incidents{inc("a", "fail", []string{"A"}, 0, -1), inc("c", "warn", []string{"C"}, 0, -1)}, HaveSnapshot: true}
	ok := Result{"ok", "ok"}
	if got := colourAt(c, 0, 1, ok); got.Level != "fail" || got.Code != "incident-high" || !slices.Equal(got.IDs, []string{"a"}) {
		t.Errorf("availability %+v", got)
	}
	if got := colourAt(c, 1, 1, Result{"ok", "verified"}); got.Level != "ok" || got.Code != "verified" || len(got.IDs) != 0 {
		t.Errorf("an availability incident coloured integrity: %+v", got)
	}
	if got := colourAt(c, 2, 1, Result{"ok", "clear"}); got.Level != "warn" || got.Code != "incident-low" || !slices.Equal(got.IDs, []string{"c"}) {
		t.Errorf("confidentiality %+v", got)
	}
}

// Availability and integrity are the worse of the measurement and the
// incidents; the code is the measurement's unless the incidents are worse.
func TestMeasurementAndIncidentsCombineByWorst(t *testing.T) {
	c := Colourer{Incidents: Incidents{inc("a", "warn", []string{"A"}, 0, -1)}, HaveSnapshot: true}
	for _, tc := range []struct {
		name        string
		m           Result
		level, code string
	}{
		{"ok measurement, incident worse", Result{"ok", "ok"}, "warn", "incident-low"},
		{"equal levels keep the measurement's code", Result{"warn", "slow"}, "warn", "slow"},
		{"measurement worse", Result{"fail", "timeout"}, "fail", "timeout"},
		{"nothing measured, incident colours it", Result{"none", "unreachable"}, "warn", "incident-low"},
	} {
		if got := colourAt(c, 0, 1, tc.m); got.Level != tc.level || got.Code != tc.code {
			t.Errorf("%s: %+v, want %s %s", tc.name, got, tc.level, tc.code)
		}
	}
	// Outside the incident the measurement stands, including "not measured".
	if got := colourAt(c, 1, 1, Result{"none", "unreachable"}); got.Level != "none" {
		t.Errorf("a slot without an incident that measured nothing must stay grey: %+v", got)
	}
	major := Colourer{Incidents: Incidents{inc("a", "fail", []string{"A"}, 0, -1)}, HaveSnapshot: true}
	if got := colourAt(major, 0, 1, Result{"warn", "slow"}); got.Level != "fail" || got.Code != "incident-high" {
		t.Errorf("a major incident over a warning: %+v", got)
	}
}

func TestConfidentialityRules(t *testing.T) {
	none := Colourer{}
	if got := colourAt(none, 2, 0, Result{"warn", "incident-low"}); got.Level != "warn" || got.Code != "incident-low" {
		t.Errorf("without a snapshot the run's own level stands: %+v", got)
	}
	with := Colourer{HaveSnapshot: true}
	if got := colourAt(with, 2, 0, Result{"warn", "incident-low"}); got.Level != "ok" || got.Code != "clear" {
		t.Errorf("with a snapshot only the incidents colour confidentiality: %+v", got)
	}
	if got := colourAt(with, 2, 0, Result{"warn", "invalid"}); got.Level != "warn" || got.Code != "invalid" {
		t.Errorf("an unreadable incident file keeps its level: %+v", got)
	}
	worse := Colourer{Incidents: Incidents{inc("c", "fail", []string{"C"}, 0, -1)}, HaveSnapshot: true}
	if got := colourAt(worse, 2, 0, Result{"warn", "invalid"}); got.Level != "fail" || got.Code != "incident-high" {
		t.Errorf("the worse of the two: %+v", got)
	}
}

// An incident reaches back to its start and ends where it was resolved; spans
// carry the incidents of every dimension.
func TestDayColoursAllDimensionsAndNamesTheIncidents(t *testing.T) {
	resolved := 6
	c := Colourer{HaveSnapshot: true, Incidents: Incidents{
		inc("a", "fail", []string{"A", "I"}, 2, resolved),
	}}
	in := DayInput{Day: day, Colour: c}
	for i := 0; i < 8; i++ {
		in.Slots[i] = slotWith(i, map[string]Dims{"vault": okDims})
	}
	got := BuildDay(in)
	l := got.Services["vault"]
	if l.Availability[:8] != "ooffffoo" || l.Integrity[:8] != "ooffffoo" || l.Confidentiality[:8] != "oooooooo" {
		t.Errorf("letters %q %q %q", l.Availability[:8], l.Integrity[:8], l.Confidentiality[:8])
	}
	var spans []string
	for _, s := range got.Spans {
		spans = append(spans, sprint(s))
	}
	want := []string{"vault|availability|2|5|fail|incident-high|a", "vault|integrity|2|5|fail|incident-high|a"}
	if !slices.Equal(spans, want) {
		t.Errorf("spans %v, want %v", spans, want)
	}
}

func TestSinceFollowsTheColouredLevel(t *testing.T) {
	c := Colourer{HaveSnapshot: true, Incidents: Incidents{inc("a", "warn", []string{"A"}, 4, 8)}}
	var chain []Slot
	for i := 0; i < 12; i++ {
		chain = append(chain, *slotWith(i, map[string]Dims{"vault": okDims}))
	}
	// ok until slot 3, warn (incident) in 4..7, ok again from 8.
	if got, reached := Since(chain, c, "vault", "availability"); !got.Equal(at(8)) || reached {
		t.Errorf("after the incident: %v %v", got, reached)
	}
	if got, _ := Since(chain[:6], c, "vault", "availability"); !got.Equal(at(4)) {
		t.Errorf("during the incident: %v", got)
	}
	if got, reached := Since(chain, Colourer{}, "vault", "availability"); !got.Equal(at(0)) || !reached {
		t.Errorf("without incidents: %v %v", got, reached)
	}
}

func TestLevelOfSeverity(t *testing.T) {
	for sev, want := range map[string]string{"low": "warn", "medium": "warn", "high": "fail", "critical": "fail"} {
		if LevelOfSeverity(sev) != want {
			t.Errorf("%s -> %s", sev, LevelOfSeverity(sev))
		}
	}
}

func TestLatestNamesTheOpenIncidentsPerDimension(t *testing.T) {
	end := at(1)
	c := Colourer{HaveSnapshot: true, Incidents: Incidents{
		inc("2026-10-01-old", "warn", []string{"A"}, 0, -1),
		inc("2026-10-01-new", "fail", []string{"A", "I"}, 0, -1),
		inc("2026-10-01-done", "fail", []string{"A"}, 0, 1),
		{ID: "z-later", Services: []string{"vault"}, Categories: []string{"A"}, Level: "warn", Start: at(1)},
	}}
	_ = end
	run := &record.CIARun{Slot: record.FormatTime(at(3)), FinishedAt: record.FormatTime(at(3).Add(8 * time.Second)),
		Services: map[string]record.CIAService{"vault": {URL: "https://v/", Availability: okDimension("healthz", "ok"),
			Integrity: okDimension("release", "verified"), Confidentiality: okDimension("incidents", "clear")}}}
	latest := BuildLatest(LatestInput{Run: run, Path: "p", FirstRun: day, Colour: c, Since: func(string, string) time.Time { return at(0) }})
	v := latest.Services["vault"]
	if want := []string{"z-later", "2026-10-01-new", "2026-10-01-old"}; !slices.Equal(v.Availability.Incidents, want) {
		t.Errorf("availability incidents %v, want %v (newest start first)", v.Availability.Incidents, want)
	}
	if !slices.Equal(v.Integrity.Incidents, []string{"2026-10-01-new"}) || len(v.Confidentiality.Incidents) != 0 {
		t.Errorf("%v %v", v.Integrity.Incidents, v.Confidentiality.Incidents)
	}
	if v.Availability.Level != "fail" || v.Availability.Code != "incident-high" || latest.Headline.Availability != "fail" {
		t.Errorf("%+v %+v", v.Availability, latest.Headline)
	}
	if want := []string{"z-later", "2026-10-01-new", "2026-10-01-old"}; !slices.Equal(latest.Incidents.Open, want) {
		t.Errorf("open %v", latest.Incidents.Open)
	}
}

func okDimension(id, code string) record.CIADimension {
	check := record.CIACheck{}
	switch id {
	case "healthz":
		check.Healthz = &record.HealthzCheck{ID: id, Level: "ok", Code: code}
	case "release":
		check.Release = &record.ReleaseCheck{ID: id, Level: "ok", Code: code}
	default:
		check.Incidents = &record.IncidentsCheck{ID: id, Level: "ok", Code: code}
	}
	return record.CIADimension{Level: "ok", Checks: []record.CIACheck{check}}
}
