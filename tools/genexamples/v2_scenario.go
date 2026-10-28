package main

import (
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// v2Start is the first slot recorded as cia-run/v2: the record before it is
// the single-vantage history the examples always had, the record from it on
// has two witnesses, and the chain runs through both without a seam.
var v2Start = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

// answer is how the secondary witness's answer to the primary fared in a slot.
type answer string

const (
	answered answer = ""         // arrived and verified
	silent   answer = "silent"   // the secondary was not reached and did nothing
	lost     answer = "lost"     // it ran and committed, but the primary never got the answer
	rejected answer = "rejected" // it answered, but the primary could not verify the answer
	partial  answer = "partial"  // it ran out of time (a cold start) and measured part of the run
)

// latamAnswers are the slots where the secondary witness's answer is not the
// plain one: a stretch of five runs in which it was silent (a witness-unavailable
// event after the third and a witness-restored after the second one back), one
// answer lost on the way, one that did not verify, and one cut short by a cold
// start. The reasons are the primary's: what it saw of the failed attempt.
var latamAnswers = parseEvents([]event{
	{from: "2026-10-01T11:25", to: "2026-10-01T11:30", code: string(silent), reason: record.ReasonTimeout},
	{from: "2026-10-01T11:35", to: "2026-10-01T11:35", code: string(silent), reason: record.ReasonUnreachable},
	{from: "2026-10-01T11:40", to: "2026-10-01T11:45", code: string(silent), reason: record.ReasonTimeout},
	{from: "2026-10-01T12:20", to: "2026-10-01T12:20", code: string(lost), reason: record.ReasonTimeout},
	{from: "2026-10-01T13:10", to: "2026-10-01T13:10", code: string(rejected), reason: record.ReasonSignature},
	{from: "2026-10-01T13:25", to: "2026-10-01T13:25", code: string(partial)},
})

// latamAvailabilityEvents are what only the secondary witness saw: the vault
// cannot be reached from Latin America for twenty minutes (amber, regional,
// never red on its own), and the edge answers one probe of sign with a bot
// challenge, which says nothing about the service.
var latamAvailabilityEvents = parseEvents([]event{
	{service: "vault", from: "2026-10-01T14:00", to: "2026-10-01T14:20", code: "timeout"},
	{service: "sign", from: "2026-10-01T13:20", to: "2026-10-01T13:20", code: "challenged"},
})

// europeDownSlot is the one run of the cia-run/v2 era in which the primary
// witness's own network failed while the secondary's did not: Latin America
// decides, and nothing is an outage.
var europeDownSlot = time.Date(2026, 10, 1, 13, 15, 0, 0, time.UTC)

// v2Plan is what the scenario says about the second witness in a slot.
type v2Plan struct {
	answer     answer
	reason     string
	europeDown bool
}

func planAt(slot time.Time) v2Plan {
	p := v2Plan{europeDown: slot.Equal(europeDownSlot)}
	for _, e := range latamAnswers {
		if !slot.Before(e.start) && !slot.After(e.end) {
			p.answer, p.reason = answer(e.code), e.reason
		}
	}
	return p
}

// ran says the secondary witness did its work in the slot, whether or not the
// primary got to know: its witness records exist and its chain moves on.
func (p v2Plan) ran() bool { return p.answer != silent }

// codeOf is what a witness saw of a service in a slot, by its code.
func codeOf(witness, service string, slot time.Time) string {
	if witness == record.WitnessLatam {
		if code, ok := codeAt(latamAvailabilityEvents, service, slot); ok {
			return code
		}
	}
	if code, ok := codeFor(availabilityEvents, witness, service, slot); ok {
		return code
	}
	return "ok"
}
