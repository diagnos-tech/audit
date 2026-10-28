package check

import (
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

func ms(v int) *int        { return &v }
func str(v string) *string { return &v }

func answer(total int) record.Probe {
	return record.Probe{Code: "ok", Attempts: 1, HTTPStatus: ms(200),
		Timings: &record.ProbeTimings{DNSMs: ms(4), ConnectMs: ms(6), TLSMs: ms(14), WaitMs: ms(20), TransferMs: ms(30), TotalMs: total}}
}

func TestProbeProblems(t *testing.T) {
	with := func(p record.Probe, f func(*record.Probe)) record.Probe { f(&p); return p }
	for _, c := range []struct {
		name string
		p    record.Probe
		want string // "" = accepted
	}{
		{"an answer", answer(90), ""},
		{"an answer that was retried", with(answer(90), func(p *record.Probe) { p.Code, p.Attempts, p.RetriedAfter = "retried", 2, str("timeout") }), ""},
		{"retried with one attempt", with(answer(90), func(p *record.Probe) { p.Code = "retried" }), "retried with 1 attempts"},
		{"two attempts without the class of the first", with(answer(90), func(p *record.Probe) { p.Attempts = 2 }), "exactly when there were two"},
		{"a class on an answer", with(answer(90), func(p *record.Probe) { p.Class = str("timeout") }), "only a failed probe has an error class"},
		{"a failure without a class", record.Probe{Code: "timeout", Attempts: 2, RetriedAfter: str("timeout")}, "names the phase it failed in"},
		{"a failure in a phase that does not exist", record.Probe{Code: "timeout", Attempts: 2, RetriedAfter: str("timeout"), Class: str("slow")}, "names the phase"},
		{"a timeout", record.Probe{Code: "timeout", Class: str("connect"), Attempts: 2, RetriedAfter: str("connect"), Timings: &record.ProbeTimings{DNSMs: ms(4), TotalMs: 3004}}, ""},
		{"a timeout that has a status", record.Probe{Code: "timeout", Class: str("timeout"), Attempts: 2, RetriedAfter: str("timeout"), HTTPStatus: ms(200)}, "a timeout has no status"},
		{"an answer that is not 200", with(answer(90), func(p *record.Probe) { p.HTTPStatus = ms(204) }), "status 200 and timings"},
		{"an answer without timings", with(answer(90), func(p *record.Probe) { p.Timings = nil }), "status 200 and timings"},
		{"challenged", record.Probe{Code: "challenged", Attempts: 1, HTTPStatus: ms(403), Timings: &record.ProbeTimings{TotalMs: 60}}, ""},
		{"not measured", record.Probe{Code: "vantage", Attempts: 2, Timings: &record.ProbeTimings{TotalMs: 7960}}, ""},
		{"a code only the combined check has", record.Probe{Code: "regional", Attempts: 1}, "not a code of a probe"},
		{"a code of nothing", record.Probe{Code: "fine", Attempts: 1}, "not a code of a probe"},
		{"three attempts", with(answer(90), func(p *record.Probe) { p.Attempts = 3 }), "attempts must be 1 or 2"},
		{"a phase longer than the attempt", with(answer(90), func(p *record.Probe) { p.Timings.WaitMs = ms(91) }), "longer than the attempt"},
		{"phases that add up to more than the attempt", with(answer(90), func(p *record.Probe) { p.Timings.TransferMs = ms(60) }), "add up to 104 ms"},
	} {
		got := strings.Join(probeProblems(c.p), "; ")
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestVantageProblems(t *testing.T) {
	timeout := record.Probe{Code: "timeout", Attempts: 2}
	blind := record.Probe{Code: "vantage", Attempts: 2}
	for _, c := range []struct {
		name string
		m    record.Measured
		want string
	}{
		{"control up, everything measured", record.Measured{Control: &record.CIAControl{OK: true}, Probes: map[string]record.Probe{"a": answer(90)}}, ""},
		{"no control probe", record.Measured{Probes: map[string]record.Probe{"a": timeout}}, ""},
		{"control up and a service down: an outage", record.Measured{Control: &record.CIAControl{OK: true}, Probes: map[string]record.Probe{"a": timeout, "b": timeout}}, ""},
		{"control down, every service failed at transport: that is not an outage", record.Measured{Control: &record.CIAControl{}, Probes: map[string]record.Probe{"a": timeout, "b": timeout}}, "vantage failure"},
		{"control down, nothing measured, as recorded", record.Measured{Control: &record.CIAControl{}, Probes: map[string]record.Probe{"a": blind, "b": blind}, Logs: map[string]record.WitnessLog{"l": {Code: "vantage"}}}, ""},
		{"control down, some measured and some not", record.Measured{Control: &record.CIAControl{}, Probes: map[string]record.Probe{"a": blind, "b": answer(90)}}, "none of them measured"},
		{"control up, ran out of time: some are not measured", record.Measured{Control: &record.CIAControl{OK: true}, Probes: map[string]record.Probe{"a": blind, "b": answer(90)}}, ""},
	} {
		got := strings.Join(vantageProblems(&c.m), "; ")
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestPeerShapeProblems(t *testing.T) {
	run := str("data/v1/cia/runs/2026/10/01/1415Z.json")
	digest := str(strings.Repeat("a", 64))
	for _, c := range []struct {
		name string
		id   string
		p    *record.WitnessPeer
		want string
	}{
		{"the primary has no peer", "europe", nil, ""},
		{"the primary with a peer", "europe", &record.WitnessPeer{Verdict: "ok"}, "no peer to check"},
		{"a secondary without a peer", "latam", nil, "checks the primary's latest record"},
		{"ok", "latam", &record.WitnessPeer{Record: run, SHA256: digest, Verdict: "ok"}, ""},
		{"gap", "latam", &record.WitnessPeer{Record: run, SHA256: digest, Verdict: "gap"}, ""},
		{"ok without the record", "latam", &record.WitnessPeer{Verdict: "ok"}, "names the record it read"},
		{"a gap without the record it read", "latam", &record.WitnessPeer{Verdict: "gap"}, "names the record it read"},
		{"could not be read, yet names a record", "latam", &record.WitnessPeer{Record: run, Verdict: "unavailable"}, "names no record"},
		{"could not be read", "latam", &record.WitnessPeer{Verdict: "unavailable"}, ""},
		{"a verdict of nothing", "latam", &record.WitnessPeer{Verdict: "fine"}, "is not ok, gap"},
		{"a record that is no run record", "latam", &record.WitnessPeer{Record: str("data/v1/latest.json"), SHA256: digest, Verdict: "gap"}, "not a run record path"},
	} {
		got := strings.Join(peerShapeProblems(c.id, c.p), "; ")
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// A secondary's check of the primary's record is held to the record: ok says it
// saw the bytes the repository has; a mismatch is a warning, because an
// immutable record cannot be made to pass by editing it.
func TestCheckPeer(t *testing.T) {
	prev := "data/v1/cia/runs/2026/10/01/1415Z.json"
	run := "data/v1/cia/runs/2026/10/01/1420Z.json"
	rd := newCIAReader(memSource{prev: []byte(`{"slot":"1415"}`)})
	good := sum([]byte(`{"slot":"1415"}`))
	for _, c := range []struct {
		name string
		p    *record.WitnessPeer
		want Status
		text string
	}{
		{"it saw what is published", &record.WitnessPeer{Record: &prev, SHA256: &good, Verdict: "ok"}, OK, "as it is published"},
		{"it saw other bytes", &record.WitnessPeer{Record: &prev, SHA256: str(strings.Repeat("0", 64)), Verdict: "ok"}, Fail, "file hashes to"},
		{"a record from the future", &record.WitnessPeer{Record: &run, SHA256: &good, Verdict: "ok"}, Fail, "not before this run"},
		{"a record outside these files", &record.WitnessPeer{Record: str("data/v1/cia/runs/2026/10/01/1000Z.json"), SHA256: &good, Verdict: "ok"}, OK, "outside these files"},
		{"it reports that the history changed", &record.WitnessPeer{Record: &prev, SHA256: &good, Verdict: "mismatch"}, Warn, "history published as"},
		{"a gap says nothing", &record.WitnessPeer{Record: &prev, SHA256: &good, Verdict: "gap"}, OK, ""},
	} {
		r := &Report{Subject: run}
		checkPeer(rd, run, "latam", c.p, r)
		var out strings.Builder
		r.Print(&out, false)
		if r.Worst() != c.want || !strings.Contains(out.String(), c.text) {
			t.Errorf("%s: worst %v, want %v containing %q:\n%s", c.name, r.Worst(), c.want, c.text, out.String())
		}
	}
}

func TestMeasuredProblems(t *testing.T) {
	run := &record.CIARunV2{Slot: "2026-10-01T14:20:00Z", FinishedAt: "2026-10-01T14:20:08Z"}
	valid := func() *record.Measured {
		return &record.Measured{Witness: "latam", Vantage: "oci:sa-saopaulo-1", Slot: run.Slot,
			StartedAt: "2026-10-01T14:20:02Z", FinishedAt: "2026-10-01T14:20:07Z", Control: &record.CIAControl{Host: "connectivity.example", OK: true},
			Probes: map[string]record.Probe{"vault": answer(90)}, Logs: map[string]record.WitnessLog{"audit": {Code: "ok", Status: "unchanged"}},
			Peer: &record.WitnessPeer{Verdict: "unavailable"}}
	}
	for _, c := range []struct {
		name string
		edit func(*record.Measured)
		want string
	}{
		{"valid", func(*record.Measured) {}, ""},
		{"another witness's measurement", func(m *record.Measured) { m.Witness = "europe" }, "the entry is latam"},
		{"another slot's", func(m *record.Measured) { m.Slot = "2026-10-01T14:15:00Z" }, "not the slot of the run"},
		{"a time that is not one", func(m *record.Measured) { m.StartedAt = "yesterday" }, "RFC 3339"},
		{"finished before it started", func(m *record.Measured) { m.FinishedAt = "2026-10-01T14:20:01Z" }, "clock skew"},
		{"a clock a day off", func(m *record.Measured) { m.StartedAt, m.FinishedAt = "2026-10-02T14:20:02Z", "2026-10-02T14:20:07Z" }, "clock skew"},
		{"a place that is not provider:region", func(m *record.Measured) { m.Vantage = "Sao Paulo" }, "provider:region"},
		{"a probe of a service the run does not have", func(m *record.Measured) { m.Probes["other"] = answer(10) }, "services of the run"},
		{"a service not probed", func(m *record.Measured) { delete(m.Probes, "vault") }, "services of the run"},
		{"a log not read", func(m *record.Measured) { delete(m.Logs, "audit") }, "logs of the run"},
		{"a probe that contradicts its code", func(m *record.Measured) { p := answer(90); p.Code = "retried"; m.Probes["vault"] = p }, "probe vault: code retried"},
		{"a log whose status contradicts its code", func(m *record.Measured) { m.Logs["audit"] = record.WitnessLog{Code: "halted", Status: "witnessed"} }, "log audit: "},
		{"a root without a size", func(m *record.Measured) {
			m.Logs["audit"] = record.WitnessLog{Code: "ok", Status: "unchanged", Root: str("x")}
		}, "without the size"},
		{"a control probe at a host that is not one", func(m *record.Measured) { m.Control.Host = "Not A Host" }, "not a host name"},
	} {
		m := valid()
		c.edit(m)
		got := strings.Join(measuredProblems("latam", m, run, []string{"vault"}, []string{"audit"}), "; ")
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
