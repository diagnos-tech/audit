# record

The v1 data files, how they are named and how they are read.

- `record.go` — witness, timestamp, finding, state, latest and index types; strict `Decode`, `Encode`
- `paths.go` — witness-record paths, times, `Kind` (what a path holds)
- `cia.go` — run record types (control, vantage, timings), the check union, levels and dimensions
- `ciaviews.go` — day, summary, latest and sync types
- `ciaincidents.go` — declared incidents and snapshots, automatic incident events, the incident list, change events
- `ciapaths.go` — CIA paths, slots and the layout patterns
- `release.go` — release manifest, verdict, healthz and signers types
- `source.go` — a local clone or a web server behind one interface; a 404 names the file and the server
- `cia_test.go` — the check union, strictness, paths and kinds
- `source_test.go` — reading over HTTP, a missing file named, other statuses told apart, paths kept inside the root