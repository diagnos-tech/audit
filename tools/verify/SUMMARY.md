# verify

The `verify` command. Opens a local clone or a web server that serves the repository's files, then runs the checks of
`internal/check`.

- `main.go` — flags, command dispatch, the report and the exit status
- `main_test.go` — the `incidents` command, usage errors, an empty repository, `cia -q` on every kind of CIA file, `release -cosign -q`
