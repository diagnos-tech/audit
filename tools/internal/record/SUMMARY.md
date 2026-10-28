# record

The v1 data files, how they are named and how they are read.

- `record.go` — witness, timestamp, finding, state, latest and index types; strict `Decode`, `Encode`
- `paths.go` — witness-record paths, times, `Kind` (what a path holds)
- `cia.go` — run record types (control, vantage, timings), the check union, levels and dimensions
- `ciarun2.go` — `cia-run/v2`: the record, its checks, `DecodeRun` (either version) and the projection the derivations read
- `measurement.go` — a witness's entry, its signed measurement, probes, timings, logs and peer check
- `ciaviews.go` — day, summary, latest and sync types
- `ciaregions.go` — the per-witness parts of the views: statistics, phases, error classes
- `ciaincidents.go` — declared incidents and snapshots, automatic incident events, the incident list, change events
- `ciapaths.go` — CIA paths, slots and the layout patterns
- `release.go` — release manifest, verdict, healthz and signers types
- `source.go` — a local clone or a web server behind one interface; a 404 names the file and the server
- `cia_test.go`, `ciarun2_test.go` — the check union, strictness, paths and kinds; both run record versions, namespaces, a fuzz target for decoding
- `testdata/` — the golden `cia-run/v2` record
- `source_test.go` — reading over HTTP, a missing file named, other statuses told apart, paths kept inside the root