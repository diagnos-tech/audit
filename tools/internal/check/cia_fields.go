package check

import (
	"fmt"
	"strings"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// checkFields checks that a check's fields agree with its code, for the codes
// where a missing or extra value would mislead a reader.
func checkFields(c record.CIACheck) []string {
	bad := func(format string, a ...any) []string {
		return []string{fmt.Sprintf("%s: %s", c.ID(), fmt.Sprintf(format, a...))}
	}
	switch {
	case c.Healthz != nil:
		h := c.Healthz
		failed := c.Level() == record.LevelFail || c.Code() == "vantage" // no answer was read
		if problems := timingsProblems(h); len(problems) > 0 {
			return problems
		}
		switch {
		case (c.Code() == "retried") != (h.Attempts == 2) && c.Level() == record.LevelOK:
			return bad("code %s with %d attempts", c.Code(), h.Attempts)
		case !failed && (h.HTTPStatus == nil || *h.HTTPStatus != 200 || h.LatencyMs == nil):
			return bad("an answer that was not a failure must have status 200 and a latency")
		case c.Code() == "timeout" && (h.HTTPStatus != nil || h.LatencyMs != nil):
			return bad("a timeout has no status and no latency")
		}
	case c.Release != nil:
		return releaseFieldProblems(c.Release)
	case c.Log != nil:
		return logFieldProblems(c.Log)
	}
	return nil
}

// timingsProblems applies the rules on a healthz check's timings: the total is
// the latency when there is one, and no phase lasts longer than the attempt.
func timingsProblems(h *record.HealthzCheck) []string {
	t := h.Timings
	if t == nil {
		return nil
	}
	if h.LatencyMs != nil && t.TotalMs != *h.LatencyMs {
		return []string{fmt.Sprintf("healthz: timings.totalMs %d is not latencyMs %d", t.TotalMs, *h.LatencyMs)}
	}
	for name, ms := range map[string]*int{"dnsMs": t.DNSMs, "connectMs": t.ConnectMs, "tlsMs": t.TLSMs, "firstByteMs": t.FirstByteMs} {
		if ms != nil && *ms > t.TotalMs {
			return []string{fmt.Sprintf("healthz: timings.%s %d is longer than the attempt (%d)", name, *ms, t.TotalMs)}
		}
	}
	return nil
}

func releaseFieldProblems(x *record.ReleaseCheck) []string {
	bad := func(msg string) []string { return []string{"release: " + msg} }
	switch x.Code {
	case "unreachable", "vantage":
		if x.Version != nil || x.Commit != nil || x.Digest != nil || x.Verdict != nil {
			return bad("an unreachable service has no release to describe")
		}
	case "unsigned":
		if x.Digest != nil || x.Verdict != nil {
			return bad("an unsigned build has no digest and no verdict")
		}
	case "pending":
		if x.Digest == nil || x.Verdict != nil || x.FirstSeen == nil {
			return bad("a pending release has a digest and a first-seen time but no verdict yet")
		}
	case "verified", "unmonitored", "served-mismatch":
		if x.Digest == nil || x.Verdict == nil || x.Version == nil || x.Commit == nil {
			return bad(x.Code + " needs the version, commit, digest and verdict")
		}
		if x.Verdict != nil && !strings.Contains(*x.Verdict, "/"+*x.Digest+"/") {
			return bad("the verdict path is not under the digest")
		}
	}
	if x.Code == "served-mismatch" && (x.Served == nil || x.Served.Mismatches == 0) {
		return bad("served-mismatch needs a sampled mismatch")
	}
	if x.Served != nil && x.Served.Checked > x.Served.Total {
		return bad("more files checked than served")
	}
	return nil
}

func logFieldProblems(x *record.LogCheck) []string {
	want := map[string]string{"unchanged": "ok", "empty": "ok", "witnessed": "ok", "finding": "finding", "halted": "halted"}
	if x.Code == "vantage" && x.Status != "error" {
		return []string{x.ID + ": a log that was not reached has status error"}
	}
	if code, known := want[x.Status]; known && code != x.Code {
		return []string{fmt.Sprintf("%s: status %s goes with code %s, not %s", x.ID, x.Status, code, x.Code)}
	}
	if (x.Status == "finding" || x.Status == "halted") && x.Finding == nil {
		return []string{x.ID + ": a finding must name the finding record"}
	}
	return nil
}

// slotTime parses a run record's slot (already validated by ciaRun).
func slotTime(rec *record.CIARun) time.Time {
	t, _ := record.ParseTime(rec.Slot)
	return t
}
