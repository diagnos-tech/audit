# examples

Invented data that mirrors the repository root, so every command works with `-root examples`. It
exists for the tools and the docs. Written by `tools/genexamples`; CI fails if the committed copy is
stale. Not real records.

- `data/` — generated: `data/v1/` holds the witness records, the hourly timestamps and tokens, the
  month indexes, `state.json` and `latest.json`, and the CIA record under `data/v1/cia/` (run records
  with their timings, incident snapshots, releases, day files with each service's latency,
  `summary.json` with the daily 95th percentile latency, `latest.json`, `incidents.json`) with `sync.json`
- `incidents/` — the incident files the snapshots are made from (input of the generator): `SUMMARY.md` lists them
- `keys/` — generated: example log, witness and authority keys, and `signers.json`
- `README.md` — what each part shows, and how to check it
