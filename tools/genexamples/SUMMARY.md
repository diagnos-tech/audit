# genexamples

Writes the example data set under `examples/`, deterministically: the witness records, the hourly
timestamps and the CIA record (run records, day files, summary, latest, incidents, releases). The
tests also check the verifier against every kind of tampering.

- `main.go` — command, output layout, the logs and authorities of the examples, the witness summaries
- `sim.go`, `sim_witness.go`, `sim_timestamp.go` — the simulated auditor run: witness, hourly record
- `keys.go`, `tsa.go`, `writer.go` — seeded keys, the example time-stamping authorities, file output
- `cia_events.go` — the scripted history: outages, slow answers, unsigned builds, auditor gaps
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
