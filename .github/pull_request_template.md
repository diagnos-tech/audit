<!-- People change code and docs; data/ is written only by the witness bot. -->

## What and why

## How I checked it

- [ ] `go test ./tools/...`, `go vet ./tools/...`, `gofmt -l tools` (prints nothing)
- [ ] `tools/ci/validate-json.sh -root examples` and `go run ./tools/verify all -root examples -openssl`
- [ ] Page changes: tried at 320 px and desktop, light and dark, keyboard only, both languages
- [ ] Format changes: the contract in the monorepo changed first; examples regenerated (`go run ./tools/genexamples`)
