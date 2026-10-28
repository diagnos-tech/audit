package cia

import (
	"slices"
	"testing"
)

// The reachability rule, for every pair of levels the two witnesses can have
// (ok, warn, fail, or none: silent, vantage, challenged) and the owner's three
// decisions: down only when the witnesses that measured agree; one failing while
// the other is up is regional (amber), never red; a witness that did not measure
// is neutral, and a lone witness that confirms a failure is a failure. The codes
// differ between the witnesses so that the code of the first one at the level
// shows.
func TestCombineReachability(t *testing.T) {
	const (
		ok1, ok2     = "retried", "ok"
		warn1, warn2 = "slow", "tls-expiring"
		fail1, fail2 = "timeout", "connect-error"
	)
	for _, c := range []struct {
		name          string
		europe, latam string
		level, code   string
	}{
		{"both up", ok1, ok2, "ok", ok1},
		{"up and slow", ok1, warn2, "warn", warn2},
		{"slow and up", warn1, ok2, "warn", warn1},
		{"both slow", warn1, warn2, "warn", warn1},
		{"both down is red, with the code of Europe", fail1, fail2, "fail", fail1},
		{"Europe down, Latin America up is regional", fail1, ok2, "warn", "regional"},
		{"Europe down, Latin America slow is regional", fail1, warn2, "warn", "regional"},
		{"Latin America down, Europe up is regional", ok1, fail2, "warn", "regional"},
		{"Latin America down, Europe slow is regional", warn1, fail2, "warn", "regional"},

		{"Europe alone, up", ok1, "", "ok", ok1},
		{"Europe alone, slow", warn1, "", "warn", warn1},
		{"Europe alone confirms a failure: red", fail1, "", "fail", fail1},
		{"Latin America alone, up", "", ok2, "ok", ok2},
		{"Latin America alone confirms a failure: red", "", fail2, "fail", fail2},
		{"Europe's network failed, Latin America decides: up", "vantage", ok2, "ok", ok2},
		{"Europe's network failed, Latin America decides: down", "vantage", fail2, "fail", fail2},
		{"Latin America's probe was challenged, Europe decides", ok1, "challenged", "ok", ok1},
		{"Latin America's probe was challenged, Europe is down", fail1, "challenged", "fail", fail1},
		{"nobody measured", "", "", "none", "vantage"},
		{"both vantage", "vantage", "vantage", "none", "vantage"},
		{"vantage and challenged", "vantage", "challenged", "none", "vantage"},
	} {
		got := CombineReachability("healthz", []Reading{{"europe", c.europe}, {"latam", c.latam}})
		if got.Level != c.level || got.Code != c.code {
			t.Errorf("%s: %s/%s, want %s/%s", c.name, got.Level, got.Code, c.level, c.code)
		}
	}
}

// The checkpoint check combines the same way, with its own codes.
func TestCombineReachabilityOfCheckpoints(t *testing.T) {
	for _, c := range []struct {
		europe, latam, level, code string
	}{
		{"ok", "ok", "ok", "ok"},
		{"unreachable", "unreachable", "fail", "unreachable"},
		{"unreachable", "ok", "warn", "regional"},
		{"ok", "unreachable", "warn", "regional"},
		{"unreachable", "", "fail", "unreachable"},
		{"vantage", "ok", "ok", "ok"},
		{"vantage", "vantage", "none", "vantage"},
	} {
		got := CombineReachability("checkpoint", []Reading{{"europe", c.europe}, {"latam", c.latam}})
		if got.Level != c.level || got.Code != c.code {
			t.Errorf("%s/%s: %s/%s, want %s/%s", c.europe, c.latam, got.Level, got.Code, c.level, c.code)
		}
	}
}

// A third witness is not special: down only when every one that measured agrees.
func TestCombineReachabilityWithThreeWitnesses(t *testing.T) {
	got := CombineReachability("healthz", []Reading{{"europe", "timeout"}, {"latam", "timeout"}, {"asia", "ok"}})
	if got.Level != "warn" || got.Code != "regional" {
		t.Errorf("two of three down: %s/%s", got.Level, got.Code)
	}
	got = CombineReachability("healthz", []Reading{{"europe", "timeout"}, {"latam", "connect-error"}, {"asia", "timeout"}})
	if got.Level != "fail" || got.Code != "timeout" {
		t.Errorf("all three down: %s/%s", got.Level, got.Code)
	}
}

// Evidence is not a quorum: a finding or a halt that either witness saw counts.
func TestCombineEvidence(t *testing.T) {
	for _, c := range []struct {
		name          string
		europe, latam string
		level, code   string
	}{
		{"both ok", "ok", "ok", "ok", "ok"},
		{"a finding in Europe only", "finding", "ok", "fail", "finding"},
		{"a halt in Latin America only", "ok", "halted", "fail", "halted"},
		{"a finding in one and a halt in the other: the first witness's code", "halted", "finding", "fail", "halted"},
		{"a log error is a warning", "ok", "log-error", "warn", "log-error"},
		{"a finding beats a log error", "log-error", "finding", "fail", "finding"},
		{"Europe's network failed, Latin America read the log", "vantage", "ok", "ok", "ok"},
		{"unreachable from one, ok from the other", "unreachable", "ok", "ok", "ok"},
		{"unreachable from both is not measured", "unreachable", "unreachable", "none", "unreachable"},
		{"one witness only, with a finding", "finding", "", "fail", "finding"},
		{"nobody read the log", "", "", "none", "vantage"},
	} {
		got := CombineEvidence([]Reading{{"europe", c.europe}, {"latam", c.latam}})
		if got.Level != c.level || got.Code != c.code {
			t.Errorf("%s: %s/%s, want %s/%s", c.name, got.Level, got.Code, c.level, c.code)
		}
	}
}

func TestCheckpointCode(t *testing.T) {
	for in, want := range map[string]string{"": "", "ok": "ok", "finding": "ok", "halted": "ok", "log-error": "ok", "unreachable": "unreachable", "vantage": "vantage"} {
		if got := CheckpointCode(in); got != want {
			t.Errorf("CheckpointCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWitnessesOrderPutsThePrimaryFirst(t *testing.T) {
	for _, in := range [][]string{{"latam", "europe"}, {"europe", "latam"}, {"zeta", "latam", "europe", "asia"}} {
		got := Witnesses(in)
		if got[0] != "europe" || !slices.IsSorted(got[1:]) {
			t.Errorf("Witnesses(%v) = %v", in, got)
		}
	}
	in := []string{"latam", "europe"}
	Witnesses(in)
	if in[0] != "latam" {
		t.Error("Witnesses sorted its argument in place")
	}
}

// Every code a reachability check can end in has the level its table says.
func TestV2CodesAddOnlyRegionalAndChallenged(t *testing.T) {
	for _, c := range []struct{ id, code, level string }{
		{"healthz", "regional", "warn"}, {"healthz", "challenged", "none"}, {"checkpoint:audit", "regional", "warn"},
	} {
		if got, ok := LevelOfCodeV2(c.id, c.code); !ok || got != c.level {
			t.Errorf("v2 %s %s = %q %v", c.id, c.code, got, ok)
		}
		if _, ok := LevelOfCode(c.id, c.code); ok {
			t.Errorf("v1 accepts %s %s, which only cia-run/v2 has", c.id, c.code)
		}
	}
	if _, ok := LevelOfCodeV2("release", "regional"); ok {
		t.Error("a release is never regional")
	}
	if got, ok := LevelOfCodeV2("healthz", "slow"); !ok || got != "warn" {
		t.Error("v2 lost a v1 code")
	}
}
