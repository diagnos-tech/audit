# tools

Go module `github.com/diagnos-tech/audit/tools`. Its own module so the data never ends up in a
module download; the root `go.work` lets every command run from the repository root. The only
dependency is `golang.org/x/mod` (for `sumdb/note`).

| Path | What |
| --- | --- |
| [`verify/`](verify) | the verifier: `go run ./tools/verify <witness\|timestamp\|finding\|consistency\|cia\|incidents\|release\|all>` (see [VERIFY.md](../VERIFY.md)) |
| [`genexamples/`](genexamples) | writes the example data set under `examples/`, deterministically; its tests also check the verifier against every kind of tampering |
| [`ci/validate-json.sh`](ci/validate-json.sh) | validates data files against `schemas/v1` with a pinned validator |
| [`internal/check`](internal/check) | every check the verifier runs, one file per kind of record |
| [`internal/cia`](internal/cia) | the CIA views derived from the facts: day files with latency (and, per witness, its statistics), the 90-day summary, the latest headline, incident colours, the incident list and the change events; how the two witnesses' results combine |
| [`internal/incidents`](internal/incidents) | the grammar and rules of `incidents/<id>.md`, implemented from the contract alone |
| [`internal/record`](internal/record) | the file types (`cia-run/v1` and `cia-run/v2`, the witnesses' measurements), their paths, strict decoding, and reading from a clone or from a web server that serves the same paths |
| [`internal/merkle`](internal/merkle) | RFC 9162 hashing, consistency proofs (build and verify), an in-memory tree |
| [`internal/tiles`](internal/tiles) | reads node hashes from a C2SP tlog-tiles log over HTTP (`tilestest` serves one in tests) |
| [`internal/cosig`](internal/cosig) | C2SP `cosignature/v1` on top of `sumdb/note`, and the plain signed-note verifier of the same key (a witness signs its measurement with it) |
| [`internal/jcs`](internal/jcs) | RFC 8785 canonical JSON, for the hourly imprint |
| [`internal/rfc3161`](internal/rfc3161) | reads a `TimeStampResp`'s fields (the signature is left to OpenSSL) |

`verify cia` recomputes every view of the CIA record (day files, summary, latest, incident list, change
events) from the run records and the incident facts with the projections of `internal/cia` and
compares what they say, whether a file is laid out compactly or indented; for a `cia-run/v2` record
it also verifies each witness's signed measurement and recomputes the combined verdicts from them.
A witness whose key is not published yet is reported, not failed. The auditor has its own
implementation of the same contract, so the two check each other. `-complete` is for the real record
(its oldest run record is the first run); the example data is a slice and is checked without it.

Each primitive is checked against an independent implementation: consistency proofs are
byte-identical to `transparency-dev/merkle`'s, the cosignature interoperates both ways with
`transparency-dev/formats` (a golden vector is in the tests), the RFC 3161 parser reads real
responses from every authority the witness uses, and the example tokens verify with
`openssl ts -verify`.

```sh
go test -race ./tools/...
go vet ./tools/... && gofmt -l tools
staticcheck ./tools/...
```
