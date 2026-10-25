# tools

Go module `github.com/diagnos-tech/audit/tools`. Its own module so the data never ends up in a
module download; the root `go.work` lets every command run from the repository root. The only
dependency is `golang.org/x/mod` (for `sumdb/note`).

| Path | What |
| --- | --- |
| [`verify/`](verify) | the verifier: `go run ./tools/verify <witness\|timestamp\|finding\|consistency\|all>` (see [VERIFY.md](../VERIFY.md)) |
| [`genexamples/`](genexamples) | writes the example data set under `examples/`, deterministically; its tests also check the verifier against every kind of tampering |
| [`ci/validate-json.sh`](ci/validate-json.sh) | validates data files against `schemas/v1` with a pinned validator |
| [`internal/check`](internal/check) | every check the verifier runs, one file per kind of record |
| [`internal/record`](internal/record) | the v1 file types, their paths, strict decoding, and reading from a clone or the published site |
| [`internal/merkle`](internal/merkle) | RFC 9162 hashing, consistency proofs (build and verify), an in-memory tree |
| [`internal/tiles`](internal/tiles) | reads node hashes from a C2SP tlog-tiles log over HTTP (`tilestest` serves one in tests) |
| [`internal/cosig`](internal/cosig) | C2SP `cosignature/v1` on top of `sumdb/note` |
| [`internal/jcs`](internal/jcs) | RFC 8785 canonical JSON, for the hourly imprint |
| [`internal/rfc3161`](internal/rfc3161) | reads a `TimeStampResp`'s fields (the signature is left to OpenSSL) |

Each primitive is checked against an independent implementation: consistency proofs are
byte-identical to `transparency-dev/merkle`'s, the cosignature interoperates both ways with
`transparency-dev/formats` (a golden vector is in the tests), the RFC 3161 parser reads real
responses from every authority the witness uses, and the example tokens verify with
`openssl ts -verify`.

```sh
go test ./tools/...
go vet ./tools/... && gofmt -l tools
```
