// Package cia computes the views of the CIA record from its facts: the day
// files, the 90-day summary, the latest headline, the incident list and the
// change events (INCIDENTS-CONTRACT, CONTRACTS §7.5). It is an independent
// implementation, written from the contract alone: the auditor has its own, and
// `verify cia` compares the two by comparing bytes.
//
// Latency. A day file carries, for each service it has, the latency of the
// service's /healthz over the day: slotsMs[i] is the latencyMs of the healthz
// check in the run record of slot i (null where the slot has no record or the
// check has no latency), samples the number of non-null entries, and p50Ms and
// p95Ms their nearest-rank percentiles: the value at 1-based position
// ceil(p*n/100) of the n sorted values, computed in integers as (p*n+99)/100;
// null, with samples 0, when there is none. The summary's p95Ms for a service
// lists, oldest day first, the p95Ms of each day's file, null for a day with no
// file or no samples.
//
// Colours. The state of an incident is the latest one: the declared incident
// in the newest snapshot, the automatic one in its event with the highest seq.
// A published incident affects a service's dimension in a slot [t, t+5min)
// when the service and the dimension's category (C, I, A) are among its own, it
// started before the slot ends and is unresolved or resolved after t. Low and
// medium severities give warn, high and critical fail. Confidentiality is only
// what the incidents with category C say (or, while no declared snapshot
// exists, what the run measured; or the worse of the two when the run could not
// read an incident file); availability and integrity are the worse of the
// measurement and the incidents, and where no incident affects a slot the
// measurement is left alone, so a slot that measured nothing stays grey. A code
// is the measurement's, unless the incidents are worse: then incident-low or
// incident-high. Days, the summary and "latest" all follow (Colourer, Since).
//
// Changes. Change events come only from the run records and the incident facts.
// Choices where the contract is silent: the first recorded slot with a measured
// level sets the state of a service and dimension without an event; a finding
// seen in the first slot is an event; a declared incident that is already
// resolved when it first appears is incident-opened, and one that changes and is
// resolved in the same snapshot is incident-resolved; record-delayed has no
// link to a record (the slot it names has none); a run is a vantage failure when
// any of its checks has code vantage; and without Complete the oldest record
// only sets the state, so events at or before the fifth recorded slot are not
// derived.
package cia
