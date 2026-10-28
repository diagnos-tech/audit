package record

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCIACheckRoundTripsEveryKind(t *testing.T) {
	for _, in := range []string{
		`{"id":"healthz","level":"ok","code":"ok","attempts":1,"httpStatus":200,"latencyMs":88,"tlsNotAfter":null,"error":null}`,
		`{"id":"checkpoint:audit","level":"fail","code":"unreachable","error":"HTTP 502"}`,
		`{"id":"release","level":"warn","code":"unsigned","version":"1","commit":null,"digest":null,"verdict":null,"firstSeen":null,"served":null,"error":null}`,
		`{"id":"log:signs","level":"ok","code":"ok","status":"unchanged","size":9,"record":null,"finding":null,"error":null}`,
		`{"id":"incidents","level":"warn","code":"incident-low","open":["2026-09-30-x"],"error":null}`,
	} {
		var c CIACheck
		if err := json.Unmarshal([]byte(in), &c); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		out, err := json.Marshal(c)
		if err != nil || string(out) != in {
			t.Errorf("round trip changed\n in: %s\nout: %s (%v)", in, out, err)
		}
		if c.ID() == "" || c.Level() == "" || c.Code() == "" {
			t.Errorf("accessors empty for %s", in)
		}
	}
}

func TestCIACheckIsStrict(t *testing.T) {
	for name, in := range map[string]string{
		"unknown id":    `{"id":"magic","level":"ok","code":"ok"}`,
		"unknown field": `{"id":"healthz","level":"ok","code":"ok","attempts":1,"httpStatus":200,"latencyMs":1,"tlsNotAfter":null,"error":null,"extra":1}`,
		"no id":         `{"level":"ok"}`,
	} {
		var c CIACheck
		if err := json.Unmarshal([]byte(in), &c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := json.Marshal(CIACheck{}); err == nil {
		t.Error("an empty check was encoded")
	}
}

func TestCIAPathsAndKinds(t *testing.T) {
	slot := time.Date(2026, 10, 1, 4, 5, 0, 0, time.UTC)
	digest := strings.Repeat("a", 64)
	for path, kind := range map[string]string{
		CIARunPath(slot):       "cia-run",
		CIAIncidentsPath(slot): "cia-incidents",
		CIADayPath(slot):       "cia-day",
		CIASummaryPath:         "cia-summary",
		CIAChangesPath:         "cia-changes",
		CIARecentPath:          "cia-changes-recent",
		"data/v1/cia/incidents/events/2026/10/01/2026-10-01-auto-vault-a-0310-1.json": "cia-incident-event",
		"data/v1/cia/incidents/events/2026/10/01/2026-10-01-auto-vault-c-0310-1.json": "",
		"data/v1/cia/incidents/events/2026/10/01/2026-10-01-auto-vault-a-0310-0.json": "",
		CIALatestPath:        "cia-latest",
		CIAIncidentsViewPath: "cia-incidents-view",
		SyncPath:             "sync",
		ReleaseDir("vault", digest) + "/verdict.json":             "release-verdict",
		ReleaseDir("vault", digest) + "/manifest.json":            "release-manifest",
		ReleaseDir("vault", digest) + "/manifest.json.sig":        "release-evidence",
		ReleaseDir("vault", digest) + "/provenance.sigstore.json": "release-evidence",
		"data/v1/cia/runs/2026/10/01/0407Z.json":                  "", // not a slot
		"data/v1/cia/other.json":                                  "",
		ReleaseDir("vault", "abc") + "/verdict.json":              "",
	} {
		if got := Kind(path); got != kind {
			t.Errorf("Kind(%s) = %q, want %q", path, got, kind)
		}
	}
	if CIARunPath(slot) != "data/v1/cia/runs/2026/10/01/0405Z.json" || CIADayPath(slot) != "data/v1/cia/days/2026/10/01.json" {
		t.Errorf("%s %s", CIARunPath(slot), CIADayPath(slot))
	}
	if !SlotOf(slot.Add(4*time.Minute + 59*time.Second)).Equal(slot) {
		t.Error("SlotOf rounds down to the five-minute slot")
	}
}

func TestSubjectKeepsTheCIALinkOnlyWhenPresent(t *testing.T) {
	without, _ := json.Marshal(Subject{Hour: "h", Logs: map[string]SubjectLog{}})
	if strings.Contains(string(without), "cia") {
		t.Errorf("%s", without)
	}
	with, _ := json.Marshal(Subject{Hour: "h", CIA: &Link{Record: "r", SHA256: "s"}, Logs: map[string]SubjectLog{}})
	if !strings.Contains(string(with), `"cia":{"record":"r","sha256":"s"}`) {
		t.Errorf("%s", with)
	}
}

func TestIncidentListItemsKeepTheirKind(t *testing.T) {
	for _, in := range []string{
		`{"id":"2026-10-01-a","source":"declared","file":"incidents/2026-10-01-a.md","blob":"` + strings.Repeat("a", 40) + `","title":{"en":"t","pt-BR":"t"},"summary":{"en":"s","pt-BR":"s"},"services":["vault"],"categories":["A"],"severity":"high","status":"resolved","declaredAt":"d","startedAt":"s","resolvedAt":"r","relates":"2026-10-01-auto-vault-a-0310","body":{"en":"b","pt-BR":"b"}}`,
		`{"id":"2026-10-01-auto-vault-a-0310","source":"auditor","categories":["A"],"services":["vault"],"severity":"high","status":"open","openedAt":"o","startedAt":"s","resolvedAt":null,"updatedAt":"u","reasons":["timeout"],"events":1,"lastEvent":"p","postmortems":[]}`,
	} {
		var item CIAListItem
		if err := json.Unmarshal([]byte(in), &item); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		out, err := json.Marshal(item)
		if err != nil || string(out) != in {
			t.Errorf("round trip changed\n in: %s\nout: %s (%v)", in, out, err)
		}
		if item.ID() == "" || item.StartedAt() != "s" {
			t.Errorf("%+v", item)
		}
	}
	for name, in := range map[string]string{
		"unknown source": `{"source":"people"}`,
		"unknown field":  `{"id":"x","source":"auditor","extra":1}`,
	} {
		var item CIAListItem
		if err := json.Unmarshal([]byte(in), &item); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := json.Marshal(CIAListItem{}); err == nil {
		t.Error("an empty item was encoded")
	}
}

func TestEventPathIsUnderTheDayOfTheRun(t *testing.T) {
	at := time.Date(2026, 10, 1, 3, 20, 0, 0, time.UTC)
	if got := CIAIncidentEventPath("2026-10-01-auto-vault-a-0310", 2, at); got != "data/v1/cia/incidents/events/2026/10/01/2026-10-01-auto-vault-a-0310-2.json" {
		t.Errorf("%s", got)
	}
}
