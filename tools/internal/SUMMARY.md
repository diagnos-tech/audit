# internal

- `check/` — every check the verifier runs, one file per kind of record
- `cia/` — the CIA projections: levels, how the witnesses' results combine, per-region statistics, day files, summary, latest, incident colours, change events
- `cosig/` — C2SP `cosignature/v1` on top of `sumdb/note`
- `incidents/` — the grammar and rules of `incidents/*.md`
- `jcs/` — RFC 8785 canonical JSON, for the hourly imprint
- `merkle/` — RFC 9162 hashing, consistency proofs, an in-memory tree
- `record/` — the file types (both run record versions, the witnesses' measurements), their paths, strict decoding, reading from a clone or a web server
- `rfc3161/` — reads a `TimeStampResp`'s fields
- `tiles/` — reads a tlog-tiles log over HTTP
