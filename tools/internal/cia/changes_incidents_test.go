package cia

import (
	"strings"
	"testing"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

func declared(id, title string, resolved bool, blob string) record.CIAIncident {
	in := record.CIAIncident{ID: id, Source: "declared", Blob: blob, Services: []string{"sign"}, Categories: []string{"C"},
		Title: record.Localized{EN: title, PTBR: title + " (pt)"}}
	if resolved {
		in.ResolvedAt = ptr("2026-10-01T00:30:00Z")
	}
	return in
}

func snap(i int, items ...record.CIAIncident) Snapshot {
	return Snapshot{Slot: at(i), Content: &record.CIAIncidents{Incidents: items}}
}

func TestDeclaredIncidentsFollowTheSnapshots(t *testing.T) {
	a, b := declared("2026-10-01-a", "A", false, "1"), declared("2026-10-01-b", "B", false, "1")
	runs := vaultRuns("ok", "ok", "ok", "ok", "ok", "ok", "ok", "ok", "ok", "ok")
	got := Changes(ChangeInput{Runs: runs, Complete: true, Snapshots: []Snapshot{
		snap(1, a),
		snap(2, a, b),
		snap(3, declared("2026-10-01-a", "A", false, "2"), b), // a edited
		snap(4, declared("2026-10-01-a", "A", true, "3"), b),  // a edited and resolved: resolved
		snap(5, declared("2026-10-01-a", "A", true, "3")),     // b withdrawn
		snap(6, declared("2026-10-01-a", "A", true, "3")),     // nothing changed
	}})
	want := []string{
		"2026-10-01-b-202610010025 incident-removed",
		"2026-10-01-a-202610010020 incident-resolved",
		"2026-10-01-a-202610010015 incident-updated",
		"2026-10-01-b-202610010010 incident-opened",
		"2026-10-01-a-202610010005 incident-opened",
	}
	var have []string
	for _, c := range got {
		have = append(have, c.ID+" "+c.Kind)
	}
	if strings.Join(have, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(have, "\n"), strings.Join(want, "\n"))
	}
	byKind := map[string]record.CIAChange{}
	for _, c := range got {
		if _, seen := byKind[c.Kind]; !seen {
			byKind[c.Kind] = c // the newest of its kind
		}
	}
	for kind, want := range map[string][2]string{
		"incident-opened":   {"Incident declared: B", "Incidente declarado: B (pt)"}, // b came after a
		"incident-updated":  {"Incident updated: A", "Incidente atualizado: A (pt)"},
		"incident-resolved": {"Incident resolved: A", "Incidente resolvido: A (pt)"},
		"incident-removed":  {"Incident removed: B", "Incidente removido: B (pt)"},
	} {
		if s := byKind[kind].Summary; s.EN != want[0] || s.PTBR != want[1] {
			t.Errorf("%s: %+v", kind, s)
		}
	}
	c := byKind["incident-removed"]
	if c.Links.Record != nil || *c.Links.Incident != "2026-10-01-b" || c.Categories[0] != "C" || c.Services[0] != "sign" {
		t.Errorf("%+v", c)
	}
}

func autoEvent(typ string, seq int, at int, resolved *string, reasons ...string) record.CIAIncidentEvent {
	return record.CIAIncidentEvent{Schema: "cia-incident-event/v1", ID: "2026-10-01-auto-vault-a-0000", Seq: seq, Type: typ,
		At: record.FormatTime(slotTime(at)), Source: "auditor", Categories: []string{"A"}, Services: []string{"vault"}, Severity: "high",
		StartedAt: record.FormatTime(slotTime(0)), ResolvedAt: resolved, Reasons: reasons, Run: record.CIARunPath(slotTime(at))}
}

func slotTime(i int) time.Time { return at(i) }

func TestAutomaticIncidentEventsBecomeChanges(t *testing.T) {
	events := []record.CIAIncidentEvent{
		autoEvent("opened", 1, 2, nil, "timeout"),
		autoEvent("updated", 2, 3, nil, "timeout", "connect-error"),
		autoEvent("resolved", 3, 5, ptr(record.FormatTime(at(4))), "timeout", "connect-error"),
	}
	got := Changes(ChangeInput{Runs: vaultRuns("ok", "ok", "ok", "ok", "ok", "ok"), Events: events, Complete: true})
	if ids(got) != "2026-10-01-auto-vault-a-0000-3 2026-10-01-auto-vault-a-0000-2 2026-10-01-auto-vault-a-0000-1" {
		t.Fatalf("%v", ids(got))
	}
	if got[2].Kind != "incident-opened" || got[2].Summary.EN != "Incident opened: vault availability (timeout)" ||
		got[2].Summary.PTBR != "Incidente aberto: vault disponibilidade (timeout)" {
		t.Errorf("%+v", got[2].Summary)
	}
	if got[1].Summary.EN != "Incident updated: vault availability (timeout, connect-error)" ||
		got[0].Summary.EN != "Incident resolved: vault availability (timeout, connect-error)" || got[0].Summary.PTBR != "Incidente resolvido: vault disponibilidade (timeout, connect-error)" {
		t.Errorf("%+v %+v", got[1].Summary, got[0].Summary)
	}
	if *got[2].Links.Incident != events[0].ID || *got[2].Links.Record != events[0].Run || got[2].Categories[0] != "A" {
		t.Errorf("%+v", got[2])
	}
}

// A slice starts from its oldest record and compares only what comes after its
// fifth recorded slot.
func TestSliceLeavesOutTheFirstFiveSlots(t *testing.T) {
	runs := vaultRuns("ok", "fail", "fail", "fail", "fail", "fail", "fail", "ok", "ok")
	full := Changes(ChangeInput{Runs: runs, Complete: true})
	slice := Changes(ChangeInput{Runs: runs})
	if len(levelEvents(full)) != 2 || len(levelEvents(slice)) != 1 || levelEvents(slice)[0].To == nil || *levelEvents(slice)[0].To != "ok" {
		t.Errorf("full %v slice %v", ids(full), ids(slice))
	}
	if short := Changes(ChangeInput{Runs: runs[:4]}); len(short) != 0 {
		t.Errorf("fewer than five records give no events: %v", ids(short))
	}
}

func TestChangesAreNewestFirstAndCapped(t *testing.T) {
	var runs []*record.CIARun
	for i := 0; i < 4*MaxChanges; i++ { // flapping every three slots
		runs = append(runs, runAt(i, map[string]record.CIAService{"vault": svc([]string{"ok", "fail"}[(i/3)%2], "ok")}))
	}
	got := changes(runs)
	if len(got) != MaxChanges {
		t.Fatalf("%d events", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].At < got[i].At {
			t.Fatalf("not newest first at %d", i)
		}
	}
}
