# check

Every check the verifier runs. Each returns a `Report` of named results (ok, warn, fail).

- `all.go` — `All`: every file under `data/v1`, the chains between them and the summaries
- `checkpoint.go`, `checkpoint_test.go` — parsing a log checkpoint
- `witness.go` — a witness record: signatures and the consistency proof from the previous one
- `consistency.go` — rebuilds consistency proofs from a log's own tiles
- `finding.go` — a finding is evidence: two signed checkpoints that conflict
- `timestamp.go` — an hourly record: imprint, subjects (including the CIA run record), chain, token
- `openssl.go` — the token's TSA signature through `openssl ts -verify`
- `keys.go` — the keyring: log and witness keys from a keys directory
- `summary.go` — `state.json`, `latest.json` and the month indexes against the records
- `report.go` — `Report`, `Result`, printing
- `cia_all.go` — `CIA`, `CIAFiles`: runs, snapshots, releases and views, in order
- `cia_run.go` — one run record: slot, code-to-level table, dimension level, check order and fields, timings, vantage and the control probe
- `cia_fields.go` — the fields a check must have for its code, and the rules on timings
- `cia_files.go` — `CIAFiles`: report on the named files of the CIA record only
- `cia_links.go` — the chain by SHA-256, the snapshot in force, verdicts and witness records it points at
- `cia_snapshot.go` — an incidents snapshot: order and the rules of each incident
- `cia_day.go` — a day file's structure and its comparison with the one derived from the runs
- `cia_events.go` — the events of automatic incidents: names, sequence, times, agreement with the run records
- `cia_coverage.go` — every failure is inside an incident; declared incidents relate to automatic ones that exist
- `cia_views.go` — day, summary, latest and incident list recomputed from the facts
- `cia_changes.go` — `changes.json` and `changes-recent.json` derived again and compared event by event
- `cia_test.go`, `cia_events_test.go` — dimension, field, latency, timings, snapshot, span, event, vantage and coverage rules
- `release.go`, `release_cosign.go` — an archived release: manifest, verdict, pinned identity, cosign
- `release_test.go` — consistency failures, manifest rules, cosign through a fake binary
- `incidents.go` — `Incidents`: incident files given as local paths
