package check

import (
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// twoWitnesses is a run of the service "vault" and the log "signs" in which
// both witnesses measured and everything is up.
func twoWitnesses() *record.CIARunV2 {
	m := func(w string) *record.Measured {
		size := uint64(9236)
		return &record.Measured{Witness: w, Probes: map[string]record.Probe{"vault": answer(90)},
			Logs: map[string]record.WitnessLog{"signs": {Code: "ok", Status: "unchanged", Size: &size, Root: str("A")}}}
	}
	return &record.CIARunV2{Slot: "2026-10-01T14:20:00Z",
		Witnesses: map[string]record.WitnessEntry{"europe": {Status: "ok", Measured: m("europe")}, "latam": {Status: "ok", Measured: m("latam")}},
		Services: map[string]record.CIAServiceV2{"vault": {
			Availability: record.CIADimensionV2{Level: "ok", Checks: []record.CIACheckV2{
				{Healthz: &record.CombinedCheck{ID: "healthz", Level: "ok", Code: "ok"}},
				{Checkpoint: &record.CombinedCheck{ID: "checkpoint:signs", Level: "ok", Code: "ok"}}}},
			Integrity: record.CIADimensionV2{Level: "ok", Checks: []record.CIACheckV2{
				{Release: &record.ReleaseCheck{ID: "release", Level: "ok", Code: "verified"}},
				{Log: &record.CombinedLog{ID: "log:signs", Level: "ok", Code: "ok"}}}},
		}}}
}

func setProbe(v2 *record.CIARunV2, witness, code string) {
	e := v2.Witnesses[witness]
	p := e.Measured.Probes["vault"]
	p.Code = code
	e.Measured.Probes["vault"] = p
	v2.Witnesses[witness] = e
}

func setLog(v2 *record.CIARunV2, witness string, l record.WitnessLog) {
	e := v2.Witnesses[witness]
	e.Measured.Logs["signs"] = l
	v2.Witnesses[witness] = e
}

func setHealthz(v2 *record.CIARunV2, level, code string, err *string) {
	svc := v2.Services["vault"]
	svc.Availability.Checks[0] = record.CIACheckV2{Healthz: &record.CombinedCheck{ID: "healthz", Level: level, Code: code, Error: err}}
	v2.Services["vault"] = svc
}

// The combined part of a record is what the signed measurements allow, and
// nothing better or worse: the failures ARCH-V2 §8.6 lists as tampering.
func TestCombinedProblems(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*record.CIARunV2)
		want string
	}{
		{"as measured", func(*record.CIARunV2) {}, ""},
		{"Latin America failed alone: regional, not red", func(v *record.CIARunV2) {
			setProbe(v, "latam", "timeout")
			setHealthz(v, "warn", "regional", str("Unreachable from Latin America (timeout); reachable from Europe."))
		}, ""},
		{"a regional failure written as a failure", func(v *record.CIARunV2) {
			setProbe(v, "latam", "timeout")
			setHealthz(v, "fail", "timeout", nil)
		}, "combine to warn/regional"},
		{"a failure of both written as regional", func(v *record.CIARunV2) {
			setProbe(v, "latam", "timeout")
			setProbe(v, "europe", "connect-error")
			setHealthz(v, "warn", "regional", str("x"))
		}, "combine to fail/connect-error"},
		{"both failed, as measured", func(v *record.CIARunV2) {
			setProbe(v, "latam", "timeout")
			setProbe(v, "europe", "timeout")
			setHealthz(v, "fail", "timeout", nil)
		}, ""},
		{"a failure hidden", func(v *record.CIARunV2) { setProbe(v, "europe", "timeout"); setProbe(v, "latam", "timeout") }, "combine to fail/timeout"},
		{"the lone witness confirms a failure: red", func(v *record.CIARunV2) {
			v.Witnesses["latam"] = record.WitnessEntry{Status: "unavailable", Reason: str("timeout")}
			setProbe(v, "europe", "timeout")
			setHealthz(v, "fail", "timeout", nil)
		}, ""},
		{"a silent witness is neutral, never an outage", func(v *record.CIARunV2) {
			v.Witnesses["latam"] = record.WitnessEntry{Status: "unavailable", Reason: str("timeout")}
		}, ""},
		{"a log halted in one witness fails the evidence check", func(v *record.CIARunV2) {
			setLog(v, "latam", record.WitnessLog{Code: "halted", Status: "halted", Finding: str("data/v1/witnesses/latam/signs/findings/2026/10/01/133509Z.json")})
		}, "log:signs is ok/ok"},
		{"the finding is that of the first witness that has one", func(v *record.CIARunV2) {
			setLog(v, "latam", record.WitnessLog{Code: "halted", Status: "halted", Finding: str("data/v1/witnesses/latam/signs/findings/2026/10/01/133509Z.json")})
			svc := v.Services["vault"]
			svc.Integrity.Checks[1] = record.CIACheckV2{Log: &record.CombinedLog{ID: "log:signs", Level: "fail", Code: "halted", Finding: str("elsewhere")}}
			v.Services["vault"] = svc
		}, "names finding \"elsewhere\""},
		{"a checkpoint unreachable from both", func(v *record.CIARunV2) {
			setLog(v, "europe", record.WitnessLog{Code: "unreachable", Status: "error"})
			setLog(v, "latam", record.WitnessLog{Code: "unreachable", Status: "error"})
		}, "checkpoint:signs is ok/ok, the witnesses' measurements combine to fail/unreachable"},
		{"a release that is vantage while the primary's probe is not", func(v *record.CIARunV2) {
			svc := v.Services["vault"]
			svc.Integrity.Checks[0] = record.CIACheckV2{Release: &record.ReleaseCheck{ID: "release", Level: "none", Code: "vantage"}}
			v.Services["vault"] = svc
		}, "release is vantage"},
	} {
		v2 := twoWitnesses()
		c.edit(v2)
		got := strings.Join(combinedProblems(v2, "vault"), "; ")
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// Two witnesses that read different roots for one size of a log, in one run, are
// a split view, which the record must name as a finding.
func TestSplitViewProblems(t *testing.T) {
	split := func(v *record.CIARunV2) {
		setLog(v, "latam", record.WitnessLog{Code: "ok", Status: "unchanged", Size: ptr64(9236), Root: str("B")})
	}
	for _, c := range []struct {
		name string
		edit func(*record.CIARunV2)
		want string
	}{
		{"the same tree", func(*record.CIARunV2) {}, ""},
		{"two trees of one size, no finding", split, "split view"},
		{"two trees of one size, the evidence check fails and names it", func(v *record.CIARunV2) {
			split(v)
			svc := v.Services["vault"]
			svc.Integrity.Checks[1] = record.CIACheckV2{Log: &record.CombinedLog{ID: "log:signs", Level: "fail", Code: "finding", Finding: str("f")}}
			v.Services["vault"] = svc
		}, ""},
		{"two trees of one size, the evidence check fails without a finding", func(v *record.CIARunV2) {
			split(v)
			svc := v.Services["vault"]
			svc.Integrity.Checks[1] = record.CIACheckV2{Log: &record.CombinedLog{ID: "log:signs", Level: "fail", Code: "finding"}}
			v.Services["vault"] = svc
		}, "split view"},
		{"two sizes prove nothing", func(v *record.CIARunV2) {
			split(v)
			e := v.Witnesses["latam"]
			e.Measured.Logs["signs"] = record.WitnessLog{Code: "ok", Status: "witnessed", Size: ptr64(9240), Root: str("B")}
			v.Witnesses["latam"] = e
		}, ""},
	} {
		v2 := twoWitnesses()
		c.edit(v2)
		got := strings.Join(splitViewProblems(v2), "; ")
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func ptr64(v uint64) *uint64 { return &v }

func TestEntryProblem(t *testing.T) {
	note, measured := str("n"), &record.Measured{}
	for _, c := range []struct {
		name string
		id   string
		e    record.WitnessEntry
		want string
	}{
		{"measured", "latam", record.WitnessEntry{Status: "ok", Note: note, Measured: measured}, ""},
		{"measured without its note: a number nobody signed", "latam", record.WitnessEntry{Status: "ok", Measured: measured}, "has its note and its measurement"},
		{"measured without a measurement", "latam", record.WitnessEntry{Status: "ok", Note: note}, "has its note and its measurement"},
		{"measured with a reason", "latam", record.WitnessEntry{Status: "ok", Note: note, Measured: measured, Reason: str("timeout")}, "no reason"},
		{"unavailable", "latam", record.WitnessEntry{Status: "unavailable", Reason: str("timeout")}, ""},
		{"not configured", "latam", record.WitnessEntry{Status: "unavailable", Reason: str("off")}, ""},
		{"unavailable without a reason", "latam", record.WitnessEntry{Status: "unavailable"}, "has a reason"},
		{"unavailable with a reason that is not one", "latam", record.WitnessEntry{Status: "unavailable", Reason: str("tired")}, "has a reason"},
		{"unavailable yet measured", "latam", record.WitnessEntry{Status: "unavailable", Reason: str("timeout"), Measured: measured}, "neither a note nor a measurement"},
		{"a status of nothing", "latam", record.WitnessEntry{Status: "maybe"}, "neither ok nor unavailable"},
		{"an id that is not one", "Latam", record.WitnessEntry{Status: "unavailable", Reason: str("off")}, "not a witness id"},
		{"an id of a directory", "witnesses", record.WitnessEntry{Status: "unavailable", Reason: str("off")}, "not a witness id"},
	} {
		if got := entryProblem(c.id, c.e); (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestV2FieldProblems(t *testing.T) {
	for _, c := range []struct {
		name string
		c    record.CIACheck
		want string
	}{
		{"a regional result says which side", record.CIACheck{Healthz: &record.HealthzCheck{ID: "healthz", Code: "regional"}}, "which side failed"},
		{"a regional result that does", record.CIACheck{Healthz: &record.HealthzCheck{ID: "healthz", Code: "regional", Error: str("x")}}, ""},
		{"a halted log without a finding", record.CIACheck{Log: &record.LogCheck{ID: "log:a", Code: "halted"}}, "names a finding exactly when"},
		{"a finding on a log that is fine", record.CIACheck{Log: &record.LogCheck{ID: "log:a", Code: "ok", Finding: str("f")}}, "names a finding exactly when"},
		{"a halted log with its finding", record.CIACheck{Log: &record.LogCheck{ID: "log:a", Code: "halted", Finding: str("f")}}, ""},
	} {
		if got := strings.Join(v2FieldProblems(c.c), "; "); (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
