package cia

import (
	"fmt"
	"sort"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// How many consecutive runs a witness has to be absent to be reported
// unavailable, and present to be reported restored: the debounce of the level
// changes, so that one lost answer is not news.
const (
	absentRuns  = 3
	presentRuns = 2
)

type presence int

const (
	unlisted      presence = iota // the run does not name the witness (a cia-run/v1 record)
	notConfigured                 // reason off: neither absent nor present
	absent                        // unavailable, or every probe vantage or challenged
	measuring
)

// presenceOf says whether a witness measured in the run: its entry says ok and
// at least one of its probes is a measurement (a probe that is vantage or
// challenged measured nothing).
func presenceOf(v2 *record.CIARunV2, witness string) presence {
	e, ok := v2.Witnesses[witness]
	switch {
	case !ok:
		return unlisted
	case e.Status != "ok" || e.Measured == nil:
		if e.Reason != nil && *e.Reason == record.ReasonOff {
			return notConfigured
		}
		return absent
	}
	for _, p := range e.Measured.Probes {
		if p.Code != "vantage" && p.Code != "challenged" {
			return measuring
		}
	}
	return absent
}

// witnessChanges derives the change events about the witnesses, which say the
// record and never the services (INCIDENTS-CONTRACT, ARCH-V2 §7.4): a witness
// absent for three consecutive runs is unavailable until it has been present for
// two; and a witnesses' disagreement, on its first run: a witness whose answer
// did not verify or whose check of the primary's record found it changed, or two
// witnesses that read different trees of one log.
func witnessChanges(runs []*record.CIARun) []record.CIAChange {
	var out []record.CIAChange
	for _, w := range v2Witnesses(runs) {
		out = append(out, availabilityOfWitness(runs, w)...)
		out = append(out, disagreements(runs, w)...)
	}
	return append(out, splitViewChanges(runs)...)
}

func v2Witnesses(runs []*record.CIARun) []string {
	seen := map[string]bool{}
	for _, r := range runs {
		if r.V2 != nil {
			for w := range r.V2.Witnesses {
				seen[w] = true
			}
		}
	}
	ids := make([]string, 0, len(seen))
	for w := range seen {
		ids = append(ids, w)
	}
	sort.Strings(ids)
	return ids
}

func availabilityOfWitness(runs []*record.CIARun, w string) []record.CIAChange {
	var out []record.CIAChange
	down := false
	var count int
	var first time.Time
	was := unlisted
	for _, r := range runs {
		if r.V2 == nil {
			continue
		}
		at, now := mustSlot(r.Slot), presenceOf(r.V2, w)
		switch now {
		case absent, measuring:
			if now != was {
				count, first = 0, at
			}
			count++
		default:
			count = 0
		}
		was = now
		switch {
		case now == absent && !down && count == absentRuns:
			out = append(out, witnessEvent(at, first, w, "unavailable", unavailableSummary(w)))
			down = true
		case now == measuring && down && count == presentRuns:
			out = append(out, witnessEvent(at, first, w, "restored", restoredSummary(w)))
			down = false
		}
	}
	return out
}

func witnessEvent(at, since time.Time, w, what string, summary record.Localized) record.CIAChange {
	e := event(fmt.Sprintf("%s-witness-%s-%s", Stamp(at), w, what), at, since, "witness-"+what)
	e.Summary = summary
	return e
}

// disagreementOf says what makes the run a disagreement of the witness: its
// answer did not verify, or it found the published history changed. "" if none.
func disagreementOf(v2 *record.CIARunV2, w string) string {
	e, ok := v2.Witnesses[w]
	switch {
	case !ok:
		return ""
	case e.Reason != nil && (*e.Reason == record.ReasonSignature || *e.Reason == record.ReasonInvalid):
		return "answer"
	case e.Measured != nil && e.Measured.Peer != nil && e.Measured.Peer.Verdict == "mismatch":
		return "peer"
	}
	return ""
}

func disagreements(runs []*record.CIARun, w string) []record.CIAChange {
	var out []record.CIAChange
	was := ""
	for _, r := range runs {
		now := ""
		if r.V2 != nil {
			now = disagreementOf(r.V2, w)
		}
		if now != "" && was == "" {
			at := mustSlot(r.Slot)
			out = append(out, witnessEvent(at, at, w, "disagreement", disagreementSummary(w, now)))
		}
		was = now
	}
	return out
}

func splitViewChanges(runs []*record.CIARun) []record.CIAChange {
	var out []record.CIAChange
	was := map[string]bool{}
	for _, r := range runs {
		now := map[string]bool{}
		if r.V2 != nil {
			for _, log := range SplitViews(r.V2) {
				now[log] = true
				if was[log] {
					continue
				}
				at := mustSlot(r.Slot)
				e := event(fmt.Sprintf("%s-log-%s-disagreement", Stamp(at), log), at, at, "witness-disagreement")
				e.Summary = splitViewSummary(log)
				e.Links.Finding = findingOf(r, log)
				out = append(out, e)
			}
		}
		was = now
	}
	return out
}

// findingOf is the finding the run's evidence check names for the log.
func findingOf(r *record.CIARun, log string) *string {
	for _, svc := range r.Services {
		for _, c := range svc.Integrity.Checks {
			if c.Log != nil && c.Log.ID == "log:"+log {
				return c.Log.Finding
			}
		}
	}
	return nil
}
