<!-- People change incidents, documents, schemas, keys and the verifier; data/ is written only by the auditor bot. -->

## What and why

## How I checked it

- [ ] `go test ./tools/...`, `go vet ./tools/...`, `gofmt -l tools` (prints nothing)
- [ ] `tools/ci/validate-json.sh -root examples` and `go run ./tools/verify all -root examples -openssl`
- [ ] An incident: `go run ./tools/verify incidents incidents/*.md`, both languages written
- [ ] Format changes: the contract in the monorepo changed first; examples regenerated (`go run ./tools/genexamples`)
