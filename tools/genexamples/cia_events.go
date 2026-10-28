package main

import (
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cia"
)

// The example history is scripted, not random: every yellow, red and grey
// stretch below is a situation the record has to describe. Times are UTC
// slot starts; both ends are included.
type event struct {
	service  string
	from, to string // 2006-01-02T15:04
	code     string
	percent  int    // latencyEvents only
	only     string // availabilityEvents only: the one witness that saw it; "" is both
	reason   string // latamAnswers only: why the answer is missing
	start    time.Time
	end      time.Time
}

const eventLayout = "2006-01-02T15:04"

func parseEvents(list []event) []event {
	out := make([]event, len(list))
	for i, e := range list {
		var err error
		if e.start, err = time.Parse(eventLayout, e.from); err != nil {
			panic(err)
		}
		if e.end, err = time.Parse(eventLayout, e.to); err != nil {
			panic(err)
		}
		out[i] = e
	}
	return out
}

// availabilityEvents are the healthz outcomes that are not plain "ok".
var availabilityEvents = parseEvents([]event{
	// The 90 days before the witness record starts (synthetic history).
	{service: "frontend", from: "2026-07-22T10:40", to: "2026-07-22T10:45", code: "slow"},
	{service: "frontend", from: "2026-08-18T16:05", to: "2026-08-18T16:10", code: "http-status"},
	{service: "frontend", from: "2026-09-14T19:20", to: "2026-09-14T19:20", code: "slow"},
	{service: "vault", from: "2026-07-30T13:05", to: "2026-07-30T13:15", code: "slow"},
	{service: "vault", from: "2026-08-12T02:10", to: "2026-08-12T02:30", code: "timeout"},
	{service: "vault", from: "2026-09-06T22:45", to: "2026-09-06T22:50", code: "slow"},
	{service: "sign", from: "2026-08-05T09:00", to: "2026-08-05T09:20", code: "slow"},
	{service: "sign", from: "2026-09-03T04:25", to: "2026-09-03T04:45", code: "connect-error"},
	{service: "sign", from: "2026-09-25T14:10", to: "2026-09-25T14:10", code: "http-status"},
	{service: "status", from: "2026-08-09T20:00", to: "2026-08-09T20:00", code: "http-status"},
	{service: "status", from: "2026-09-21T12:05", to: "2026-09-21T12:05", code: "slow"},
	// The window the witness records cover.
	{service: "status", from: "2026-09-30T12:50", to: "2026-09-30T12:50", code: "retried", only: "europe"},
	{service: "vault", from: "2026-09-30T15:30", to: "2026-09-30T15:35", code: "slow"},
	{service: "sign", from: "2026-09-30T19:25", to: "2026-09-30T19:25", code: "slow"},
	{service: "sign", from: "2026-09-30T22:10", to: "2026-09-30T22:10", code: "retried", only: "europe"},
	{service: "vault", from: "2026-10-01T03:10", to: "2026-10-01T03:25", code: "timeout"},
	{service: "frontend", from: "2026-10-01T07:35", to: "2026-10-01T07:35", code: "retried", only: "europe"},
	{service: "frontend", from: "2026-10-01T10:00", to: "2026-10-01T10:00", code: "slow"},
	{service: "sign", from: "2026-10-01T11:05", to: "2026-10-01T11:10", code: "slow"},
	{service: "vault", from: "2026-10-01T12:40", to: "2026-10-01T12:40", code: "retried", only: "europe"},
	// The two witnesses disagree about nothing here: the services are down for both.
	{service: "frontend", from: "2026-10-01T12:50", to: "2026-10-01T13:05", code: "http-status"},
	// Only Europe measured, and it confirmed the failure: down, because nobody contradicts it.
	{service: "sign", from: "2026-10-01T11:30", to: "2026-10-01T11:35", code: "connect-error", only: "europe"},
})

// integrityEvents are the release outcomes that are not "verified". A service
// whose healthz fails has no release check at all (unreachable).
var integrityEvents = parseEvents([]event{
	{service: "sign", from: "2026-07-28T17:15", to: "2026-07-28T17:15", code: "pending"},
	{service: "vault", from: "2026-08-04T15:00", to: "2026-08-04T15:00", code: "pending"},
	{service: "status", from: "2026-08-20T13:05", to: "2026-08-20T13:05", code: "pending"},
	{service: "sign", from: "2026-08-27T14:10", to: "2026-08-27T15:00", code: "served-mismatch"},
	{service: "vault", from: "2026-09-22T11:30", to: "2026-09-22T11:30", code: "pending"},
	// A hot fix deployed by hand, without evidence, until a signed release replaced it.
	{service: "frontend", from: "2026-09-27T14:00", to: "2026-10-01T09:55", code: "unsigned"},
	{service: "frontend", from: "2026-10-01T10:00", to: "2026-10-01T10:00", code: "pending"},
})

// latencyEvents are stretches in which a healthy service answered slower than
// usual (percent of its normal latency): a release that regressed and was
// fixed, a busy week.
var latencyEvents = parseEvents([]event{
	{service: "vault", from: "2026-08-04T15:05", to: "2026-08-10T09:00", percent: 190},
	{service: "sign", from: "2026-09-10T08:00", to: "2026-09-13T20:00", percent: 165},
	{service: "frontend", from: "2026-07-21T00:00", to: "2026-07-22T23:55", percent: 150},
})

// latencyPercent is how much of its normal latency a service takes at t.
func latencyPercent(service string, slot time.Time) int {
	for _, e := range latencyEvents {
		if e.service == service && !slot.Before(e.start) && !slot.After(e.end) {
			return e.percent
		}
	}
	return 100
}

// auditorGaps are the stretches in which the auditor did not run at all: no
// run record, no witness record, grey in every view.
var auditorGaps = parseGaps([][2]string{
	{"2026-07-19T00:00", "2026-07-19T23:55"},
	{"2026-08-23T00:00", "2026-08-23T23:55"},
	{"2026-09-08T06:00", "2026-09-08T11:25"},
	{"2026-09-30T00:00", "2026-09-30T10:55"}, // before the witness started
	{"2026-10-01T05:00", "2026-10-01T05:15"},
})

type gap struct{ start, end time.Time }

func parseGaps(list [][2]string) []gap {
	out := make([]gap, len(list))
	for i, g := range list {
		s, err1 := time.Parse(eventLayout, g[0])
		e, err2 := time.Parse(eventLayout, g[1])
		if err1 != nil || err2 != nil {
			panic("bad gap")
		}
		out[i] = gap{s, e}
	}
	return out
}

func inGap(slot time.Time) bool {
	for _, g := range auditorGaps {
		if !slot.Before(g.start) && !slot.After(g.end) {
			return true
		}
	}
	return false
}

func codeAt(events []event, service string, slot time.Time) (string, bool) {
	return codeFor(events, "", service, slot)
}

// codeFor is codeAt as the named witness saw it: an event that only the other
// witness saw is not there. With no witness named, every event is.
func codeFor(events []event, witness, service string, slot time.Time) (string, bool) {
	for _, e := range events {
		if e.service == service && !slot.Before(e.start) && !slot.After(e.end) && (e.only == "" || witness == "" || e.only == witness) {
			return e.code, true
		}
	}
	return "", false
}

// probe is what the scenario says the auditor saw of one service in a slot.
type probe struct{ healthz, release string }

func probeAt(service string, slot time.Time) probe {
	p := probe{healthz: "ok", release: "verified"}
	if code, ok := codeAt(availabilityEvents, service, slot); ok {
		p.healthz = code
	}
	if level, _ := cia.LevelOfCode("healthz", p.healthz); level == "fail" {
		p.release = "unreachable"
		return p
	}
	if code, ok := codeAt(integrityEvents, service, slot); ok {
		p.release = code
	}
	return p
}

// The services, in the order the run records list them; logs are the transparency logs the audit service covers.
var (
	serviceIDs = []string{"frontend", "sign", "status", "vault"}
	auditLogs  = []string{"audit", "signs"}
)
