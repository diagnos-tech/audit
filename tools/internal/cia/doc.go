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
//
// Witnesses. A cia-run/v2 record holds the measurements of several witnesses and
// the combined verdicts of the services. Combine* are the rules (a service is down
// only when the witnesses that measured agree; one failing while another is up is
// regional, a warning; a witness that measured nothing is neutral; evidence takes
// the worst witness), and the verifier recomputes the combined verdicts with them.
// Everything the views derive from the verdicts is the same for both versions of the
// record, so the derivations read a cia-run/v2 record through its projection
// (record.CIARunV2.AsRun) and only the per-witness parts, below, look inside it.
//
// Regions. A day file also carries, for each service and witness, the day as that
// witness saw it: its probe's level in every slot (o, w, f, or - where the slot has no
// record or the witness measured nothing), the totalMs of every probe that succeeded
// (slotsMs; failures, timeouts included, are errors and not latency samples), their
// minimum (p0), nearest-rank p50, p75, p90, p95 and p99, maximum (p100) and mean (the
// sum doubled plus n, over twice n: rounded half up in integers), the mean, median and
// p95 of each phase of the time, the failures by class, the slots that needed a retry
// and the uptime. For a cia-run/v1 record, which has one vantage point, the
// primary witness's probe is read from its healthz check (probeOfV1): the class
// follows the code and the status, the wait is firstByteMs less the three phases
// before it, and the transfer is totalMs less firstByteMs. The summary copies each
// region's days, uptime and daily p50 and p95 from the day files; latest.json names
// each witness's probe and status, and since when.
//
// Witness events. A witness absent for three consecutive runs (unavailable, or
// every probe vantage or challenged) is reported unavailable, on the third and since
// the first; present for two it is restored; a witness that is off, or a run that
// does not name it, resets the count. A disagreement is reported on its first run:
// an answer that did not verify (reason signature or invalid), a peer check that
// found the published history changed, or, per log, two witnesses that read two roots
// for one size. A level change whose slot is regional names the region that failed.
package cia
