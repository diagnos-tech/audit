package cia

import (
	"slices"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

func TestIncidentListWithoutASnapshot(t *testing.T) {
	list := BuildIncidentList("", nil, nil)
	if list.Declared != nil || list.Incidents == nil || len(list.Incidents) != 0 {
		t.Errorf("%+v", list)
	}
}

func TestIncidentListMergesDeclaredAndAutomatic(t *testing.T) {
	auto := "2026-10-01-auto-vault-a-0000"
	resolved := record.FormatTime(at(4))
	events := FoldEvents([]record.CIAIncidentEvent{
		autoEvent("resolved", 2, 5, &resolved, "timeout"), // out of order on purpose
		autoEvent("opened", 1, 2, nil, "timeout"),
	})
	snapshot := &record.CIAIncidents{ReadAt: "2026-10-01T00:30:02Z", Source: record.CIAIncidentsSource{Commit: "c"},
		Incidents: []record.CIAIncident{
			{ID: "2026-10-01-b", Source: "declared", StartedAt: record.FormatTime(at(1))},
			{ID: "2026-10-01-a", Source: "declared", StartedAt: record.FormatTime(at(1))},
			{ID: "2026-10-01-pm", Source: "declared", StartedAt: record.FormatTime(at(0)), Relates: &auto},
			{ID: "2026-10-01-pm2", Source: "declared", StartedAt: record.FormatTime(at(0)), Relates: &auto},
		}}
	list := BuildIncidentList("data/v1/cia/incidents/2026/10/01/0030Z.json", snapshot, events)
	if list.Declared == nil || list.Declared.Commit != "c" || list.Declared.ReadAt != "2026-10-01T00:30:02Z" {
		t.Errorf("%+v", list.Declared)
	}
	var got []string
	for _, it := range list.Incidents {
		got = append(got, it.ID())
	}
	// startedAt descending (the automatic one started at slot 0), ties by id.
	want := []string{"2026-10-01-a", "2026-10-01-b", "2026-10-01-auto-vault-a-0000", "2026-10-01-pm", "2026-10-01-pm2"}
	if !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	a := list.Incidents[2].Auto
	if a == nil || a.Status != "resolved" || a.Events != 2 || a.OpenedAt != record.FormatTime(at(2)) || a.UpdatedAt != record.FormatTime(at(5)) ||
		a.LastEvent != "data/v1/cia/incidents/events/2026/10/01/"+auto+"-2.json" || !slices.Equal(a.Postmortems, []string{"2026-10-01-pm", "2026-10-01-pm2"}) {
		t.Errorf("%+v", a)
	}
	open := BuildIncidentList("", nil, FoldEvents([]record.CIAIncidentEvent{autoEvent("opened", 1, 2, nil, "timeout")}))
	if s := open.Incidents[0].Auto; s.Status != "open" || s.ResolvedAt != nil || len(s.Postmortems) != 0 || s.Postmortems == nil {
		t.Errorf("%+v", s)
	}
}

func TestFoldEventsOrdersBySeq(t *testing.T) {
	byID := FoldEvents([]record.CIAIncidentEvent{autoEvent("updated", 2, 3, nil, "a"), autoEvent("opened", 1, 2, nil, "a")})
	list := byID["2026-10-01-auto-vault-a-0000"]
	if len(list) != 2 || list[0].Seq != 1 || list[1].Seq != 2 {
		t.Errorf("%+v", list)
	}
	incs, err := FromEvents(byID)
	if err != nil || len(incs) != 1 || !incs[0].Auto || incs[0].Level != "fail" || incs[0].End != nil {
		t.Errorf("%+v %v", incs, err)
	}
}
