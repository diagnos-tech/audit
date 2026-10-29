# genexamples

Writes the example data set under `examples/`, deterministically: the witness records, the hourly
timestamps and the CIA record (run records, day files, summary, latest, incidents, releases). The
tests also check the verifier against every kind of tampering.

- `main.go` — command, output layout, the logs and authorities of the examples, the witness summaries
- `sim.go`, `sim_witness.go`, `sim_timestamp.go` — the simulated auditor run: witness, hourly record
- `keys.go`, `tsa.go`, `writer.go` — seeded keys, the example time-stamping authorities, file output
- `cia_events.go` — the scripted history: outages, slow answers, unsigned builds, auditor gaps
- `v2_scenario.go` — from 10:00Z on 1 October the run records have two witnesses: when the second one is silent, loses an answer, is rejected, runs out of time, or cannot reach a service
- `v2_probe.go`, `v2_run.go`, `v2_notes.go` — what each witness saw, the signed measurements and the combined run record
- `sim_witness2.go` — the second witness's own chain of records, in its own namespace
- `cia_run.go`, `cia_checks.go` — build one run record from the scenario and the witness outcomes
- `cia_history.go` — the months before the witness records begin (in memory), the first-run link
- `cia_incidents.go` — the four declared-incident snapshots, derived from `examples/incidents/` (and one withdrawn declaration)
- `cia_auto.go` — the auditor's policy for the incidents it opens on its own, played over the history
- `cia_release.go`, `cia_releases_data.go` — the example releases: manifests and verdicts
- `cia_views.go` — event facts, day files, summary, latest, incident list, changes and cursor, from the shared projections
- `cia_fake.go` — deterministic stand-ins for commit ids and latency jitter
- `examples_test.go` — examples verify, committed copy is current, witness tampering, consistency
- `cia_incidents_test.go` — incident, event, change and vantage tampering is caught
- `cia_test.go` — CIA run record, day, summary and release tampering is caught
- `cia_examples_test.go` — `-complete` rejects the slice, the history has every state, the latency follows the run records, a server without some records fails clearly
- `v2_examples_test.go` — the chain crosses the version boundary, every scripted situation is in the examples, the size budget, the cosignatures are reproducible
- `v2_complete_test.go` — a history that begins with its first run verifies with `-complete`, regions included
- `v2_budget_test.go` — the size budget of the records and views, and the cosignatures recomputed from the specification
- `v2_tamper_test.go` — a number, a note, a combined verdict, a namespace, a split view, a peer mismatch changed: caught
- `v2_keys_test.go` — an absent second witness key is not a failure, a wrong one is; after a key rotation the published records still verify
