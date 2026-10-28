# schemas/v1

JSON Schema 2020-12 for every data file. Their `$id`s stay under `diagnos-tech.github.io/audit/`.
These files are shared byte for byte with the auditor and the services.

- `cia-changes-recent.schema.json` — the newest 30 change events, the head of `cia-changes` (a view)
- `cia-changes.schema.json` — the last 500 change events, newest first (a view)
- `cia-day.schema.json` — a day of five-minute slots per service and dimension, its spans and its latency, with the latency of each of its 288 slots, and per witness its letters, latency statistics, phases and errors (a view)
- `cia-incident-event.schema.json` — one change of an automatic incident: opened, updated or resolved
- `cia-incident-list.schema.json` — declared and automatic incidents in one list (a view)
- `cia-incidents.schema.json` — a snapshot of the declared incidents, with the blob of each file
- `cia-latest.schema.json` — the headline and the state of each service after the latest run, and of each witness (a view)
- `cia-release.schema.json` — the verdict on one release and where its evidence is archived
- `cia-run-v2.schema.json` — one five-minute run measured by several witnesses: each witness's signed measurement, and the combined levels, checks and codes per service; same path and chain as `cia-run`
- `cia-run.schema.json` — one five-minute run seen from one place: levels, checks, codes and probe timings per service, chained to the previous run
- `cia-summary.schema.json` — the 90-day summary with per-day counts, uptime and p95 latency, and per witness its days, uptime and daily p50 and p95 (a view)
- `defs.schema.json` — definitions shared by the other schemas (ids, times, digests, hashes, paths, levels, and the witnesses' probes, measurements, statistics)
- `finding.schema.json` — evidence that a log misbehaved
- `healthz.schema.json` — what every service answers at `/healthz`
- `index.schema.json` — a month's list of witness records
- `latest.schema.json` — the witness summary the page reads first
- `release-manifest.schema.json` — every file of a release with its digest, the artifact that is signed
- `signers.schema.json` — the pinned CI identity whose signature a release needs (`keys/signers.json`)
- `state.schema.json` — the witness's own state
- `sync.schema.json` — how far the auditor's storage has been mirrored here
- `timestamp.schema.json` — an hourly record: subject, imprint, token and the link to the run chain
- `witness.schema.json` — one cosigned checkpoint and its consistency proof, by either witness
