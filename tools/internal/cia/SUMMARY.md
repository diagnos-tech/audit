# cia

The views of the CIA record, derived from its facts (CONTRACTS §7.5, INCIDENTS-CONTRACT). Written from
the contract alone; the auditor has its own implementation and `verify cia` compares bytes. `doc.go`
says what the latency fields, the incident colours and the change events mean, and where the contract
left a choice.

- `doc.go` — the rules, in words
- `levels.go` — levels, letters, the code-to-level table (and the codes only `cia-run/v2` has)
- `combine.go` — how the witnesses' results combine: reachability by agreement, evidence by the worst
- `stats.go` — nearest-rank percentiles, the mean, a witness's latency statistics and phases
- `probe.go` — what a witness saw of a service in a run, from either record version
- `regions.go`, `regional.go` — per-witness day, summary and latest parts; the region that failed
- `splitview.go` — two witnesses that read two roots for one size of a log
- `slot.go` — a run as the projections see it, `since`, service lists
- `incidents.go` — published incidents (declared and automatic) in their latest state, and which ones affect a service
- `colour.go` — `Colourer`: a measurement coloured by the incidents
- `day.go` — the day file: letters, runs, spans, latency
- `latency.go` — nearest-rank percentiles and the latency entry of a day
- `summary.go` — the day letter rule, counts, the 90-day summary, uptime, daily p95
- `latest.go` — the latest headline
- `list.go` — the incident list (declared plus automatic, folded from their events)
- `changes.go` — the change events view: what is derived, the slice rule, the order
- `changes_levels.go` — level changes with debounce, releases, findings, gaps and vantage failures
- `changes_incidents.go` — change events of automatic and declared incidents
- `changes_witness.go` — change events of the witnesses: unavailable, restored, disagreement, split view
- `changes_text.go` — the fixed summaries in both languages
- `cia_test.go`, `colour_test.go`, `latency_test.go`, `list_test.go`, `changes_test.go`, `changes_incidents_test.go` — every threshold, rule and template