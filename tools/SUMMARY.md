# tools

Go module `github.com/diagnos-tech/audit/tools`: everything that checks the record and builds the
example data. Standard library plus `golang.org/x/mod`; its own module so the
data never ends up in a module download.

- `ci/` — the JSON Schema validation script CI runs
- `genexamples/` — writes the deterministic example data set under `examples/`
- `internal/` — the packages the commands share
- `verify/` — the verifier: witness, timestamp, finding, consistency, cia, incidents, release, all (both run record versions, both witnesses)
- `go.mod`, `go.sum` — the module and its only dependency
- `README.md` — the commands, and how each primitive is checked against an independent implementation
