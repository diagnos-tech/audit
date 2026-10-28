package cia

import (
	"fmt"
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// svc builds a service of a run record with the given availability and integrity
// levels (the codes follow from the levels well enough for the derivation).
func svc(avail, integ string) record.CIAService {
	code := map[string]string{"ok": "ok", "warn": "slow", "fail": "timeout", "none": "unreachable"}[avail]
	icode := map[string]string{"ok": "verified", "warn": "unsigned", "fail": "signature-invalid", "none": "unreachable"}[integ]
	return record.CIAService{
		Availability: record.CIADimension{Level: avail, Checks: []record.CIACheck{{Healthz: &record.HealthzCheck{ID: "healthz", Level: avail, Code: code}}}},
		Integrity:    record.CIADimension{Level: integ, Checks: []record.CIACheck{{Release: &record.ReleaseCheck{ID: "release", Level: integ, Code: icode}}}},
	}
}

func runAt(i int, services map[string]record.CIAService) *record.CIARun {
	return &record.CIARun{Slot: record.FormatTime(at(i)), Services: services}
}

// vaultRuns makes one run per availability level for vault at consecutive slots
// from slot 0.
func vaultRuns(levels ...string) []*record.CIARun {
	var runs []*record.CIARun
	for i, l := range levels {
		runs = append(runs, runAt(i, map[string]record.CIAService{"vault": svc(l, "ok")}))
	}
	return runs
}

func changes(runs []*record.CIARun) []record.CIAChange {
	return Changes(ChangeInput{Runs: runs, Complete: true})
}

func ids(cs []record.CIAChange) string {
	var out []string
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return strings.Join(out, " ")
}

func TestAvailabilityLevelChangesAreDebounced(t *testing.T) {
	for _, c := range []struct {
		name   string
		levels []string
		want   []string // "from>to@at/since" in slots, oldest first
	}{
		{"steady", []string{"ok", "ok", "ok", "ok"}, nil},
		{"worse needs three", []string{"ok", "ok", "fail", "fail", "fail", "fail"}, []string{"ok>fail@4/2"}},
		{"two failures are not enough", []string{"ok", "fail", "fail", "ok", "ok"}, nil},
		{"a good slot resets the window", []string{"ok", "fail", "fail", "ok", "fail", "fail", "fail"}, []string{"ok>fail@6/4"}},
		{"better needs two", []string{"ok", "fail", "fail", "fail", "ok", "fail", "fail", "fail", "ok", "ok"}, []string{"ok>fail@3/1", "fail>ok@9/8"}},
		{"warning needs three too", []string{"ok", "warn", "warn", "warn"}, []string{"ok>warn@3/1"}},
		{"fail to warn is better", []string{"fail", "fail", "fail", "warn", "warn"}, []string{"fail>warn@4/3"}},
		{"slots that measured nothing neither count nor interrupt", []string{"ok", "fail", "none", "fail", "none", "fail"}, []string{"ok>fail@5/1"}},
		{"the first slot sets the state", []string{"fail", "fail", "fail", "fail"}, nil},
		{"a first slot that measured nothing sets nothing", []string{"none", "fail", "fail", "ok", "ok", "ok"}, []string{"fail>ok@4/3"}},
		{"a different candidate restarts the window", []string{"ok", "warn", "warn", "fail", "fail", "fail"}, []string{"ok>fail@5/3"}},
	} {
		var got []string
		for _, e := range levelEvents(changes(vaultRuns(c.levels...))) {
			got = append(got, fmt.Sprintf("%s>%s@%d/%d", *e.From, *e.To, slotIndex(e.At), slotIndex(e.Since)))
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func levelEvents(cs []record.CIAChange) []record.CIAChange {
	var out []record.CIAChange
	for i := len(cs) - 1; i >= 0; i-- { // oldest first
		if cs[i].Kind == "level-changed" {
			out = append(out, cs[i])
		}
	}
	return out
}

func slotIndex(s string) int { return int(mustSlot(s).Sub(day) / record.SlotLength) }

func TestIntegrityLevelChangesAtOnce(t *testing.T) {
	var runs []*record.CIARun
	for i, l := range []string{"warn", "warn", "ok", "ok", "fail", "ok"} {
		runs = append(runs, runAt(i, map[string]record.CIAService{"frontend": svc("ok", l)}))
	}
	e := levelEvents(changes(runs))
	if len(e) != 3 || *e[0].From != "warn" || *e[0].To != "ok" || slotIndex(e[0].At) != 2 || *e[2].To != "ok" {
		t.Fatalf("%v", ids(e))
	}
	if e[0].Summary.EN != "frontend integrity: unverified → verified" || e[0].Summary.PTBR != "frontend integridade: não verificada → verificada" {
		t.Errorf("%+v", e[0].Summary)
	}
	if e[1].Summary.EN != "frontend integrity: verified → failed" || e[1].Categories[0] != "I" || *e[1].Dimension != "integrity" {
		t.Errorf("%+v", e[1])
	}
	if e[0].ID != "202610010010-frontend-integrity-level" || e[0].Links.Record == nil || *e[0].Links.Record != record.CIARunPath(at(2)) {
		t.Errorf("%+v", e[0])
	}
}

func TestAvailabilityWordsInBothLanguages(t *testing.T) {
	e := levelEvents(changes(vaultRuns("ok", "ok", "fail", "fail", "fail", "ok", "ok")))
	if e[0].Summary.EN != "vault availability: up → down" || e[0].Summary.PTBR != "vault disponibilidade: no ar → fora do ar" {
		t.Errorf("%+v", e[0].Summary)
	}
	if e[1].Summary.EN != "vault availability: down → up" {
		t.Errorf("%+v", e[1].Summary)
	}
}

func withRelease(i int, service, version, digest string) *record.CIARun {
	s := svc("ok", "ok")
	verdict := "data/v1/cia/releases/" + service + "/" + digest + "/verdict.json"
	s.Integrity.Checks[0].Release.Version, s.Integrity.Checks[0].Release.Digest, s.Integrity.Checks[0].Release.Verdict = &version, &digest, &verdict
	return runAt(i, map[string]record.CIAService{service: s})
}

func TestReleaseVerifiedOnANewDigest(t *testing.T) {
	d1, d2 := strings.Repeat("1", 64), strings.Repeat("2", 64)
	runs := []*record.CIARun{withRelease(0, "vault", "1.0", d1), withRelease(1, "vault", "1.0", d1), withRelease(2, "vault", "1.1", d2),
		withRelease(3, "vault", "1.1", d2), withRelease(4, "vault", "1.0", d1)}
	got := changes(runs)
	if len(got) != 2 || got[0].ID != "202610010020-vault-integrity-release" || got[1].At != record.FormatTime(at(2)) {
		t.Fatalf("%v", ids(got))
	}
	if got[1].Summary.EN != "vault: release 1.1 verified" || got[1].Summary.PTBR != "vault: versão 1.1 verificada" {
		t.Errorf("%+v", got[1].Summary)
	}
	if got[0].Links.Release == nil || !strings.Contains(*got[0].Links.Release, d1) {
		t.Errorf("a return to an older digest is a new verification: %+v", got[0].Links)
	}
}

func withFinding(i int, finding string) *record.CIARun {
	s := svc("ok", "fail")
	path := "data/v1/signs/findings/" + finding + ".json"
	s.Integrity.Checks = append(s.Integrity.Checks, record.CIACheck{Log: &record.LogCheck{ID: "log:signs", Level: "fail", Code: "finding", Finding: &path}})
	return runAt(i, map[string]record.CIAService{"audit": s})
}

func TestFindingIsReportedOnce(t *testing.T) {
	got := changes([]*record.CIARun{runAt(0, map[string]record.CIAService{"audit": svc("ok", "ok")}), withFinding(1, "a"), withFinding(2, "a"), withFinding(3, "b")})
	var findings []record.CIAChange
	for _, c := range got {
		if c.Kind == "finding" {
			findings = append(findings, c)
		}
	}
	if len(findings) != 2 || findings[1].Summary.EN != "Witness finding in log signs" || findings[1].Summary.PTBR != "Achado da testemunha no log signs" {
		t.Fatalf("%v", ids(findings))
	}
	if findings[0].Links.Finding == nil || *findings[0].Links.Finding != "data/v1/signs/findings/b.json" || findings[0].At != record.FormatTime(at(3)) {
		t.Errorf("%+v", findings[0])
	}
}

func TestMissingRecordsAreDelaysNotOutages(t *testing.T) {
	mk := func(slots ...int) []*record.CIARun {
		var runs []*record.CIARun
		for _, s := range slots {
			runs = append(runs, runAt(s, map[string]record.CIAService{"vault": svc("ok", "ok")}))
		}
		return runs
	}
	if got := changes(mk(0, 1, 4)); len(got) != 0 {
		t.Errorf("two missing slots are not a delay: %v", ids(got))
	}
	got := changes(mk(0, 1, 5, 6)) // slots 2, 3 and 4 are missing: 15 minutes
	if len(got) != 2 || got[0].ID != "202610010025-record-resumed" || got[1].ID != "202610010010-record-delayed" {
		t.Fatalf("%v", ids(got))
	}
	delayed, resumed := got[1], got[0]
	if delayed.Summary.EN != "The record was delayed for 15 minutes; this is not an outage of the services" ||
		delayed.Summary.PTBR != "O registro atrasou 15 minutos; isso não é uma queda dos serviços" ||
		resumed.Summary.EN != "The record resumed after 15 minutes" || resumed.Summary.PTBR != "O registro voltou depois de 15 minutos" {
		t.Errorf("%+v %+v", delayed.Summary, resumed.Summary)
	}
	if len(delayed.Services) != 0 || len(delayed.Categories) != 0 || delayed.Links.Record != nil || resumed.Links.Record == nil || delayed.Since != delayed.At {
		t.Errorf("%+v %+v", delayed, resumed)
	}
	if len(levelEvents(got)) != 0 {
		t.Error("a delay of the record changed a level")
	}
}

func vantageRun(i int) *record.CIARun {
	s := svc("none", "none")
	s.Availability.Checks[0].Healthz.Code = "vantage"
	return runAt(i, map[string]record.CIAService{"vault": s})
}

func TestVantageFailuresAreReportedOncePerStreak(t *testing.T) {
	ok := func(i int) *record.CIARun { return runAt(i, map[string]record.CIAService{"vault": svc("ok", "ok")}) }
	got := changes([]*record.CIARun{ok(0), vantageRun(1), vantageRun(2), ok(3), vantageRun(4)})
	if ids(got) != "202610010020-record-vantage 202610010005-record-vantage" {
		t.Fatalf("%v", ids(got))
	}
	if got[0].Kind != "vantage" || !strings.Contains(got[0].Summary.EN, "not an outage") || got[0].Services == nil || len(got[0].Categories) != 0 {
		t.Errorf("%+v", got[0])
	}
	if len(levelEvents(got)) != 0 {
		t.Error("a vantage failure changed a level")
	}
}
