# audit

The public, independent record of the confidentiality, integrity and availability of diagnos, and of
the witness of its transparency logs. The diagnos auditor commits the same public data it publishes
to its bucket here, every five minutes; people declare incidents and change the documents, schemas,
keys and verifier. Start with README.md.

- `.github/` — workflows (check, data, watchdog), issue and pull request templates, code owners, Dependabot
- `data/` — the record, written only by the auditor: run records (one or two witnesses), release evidence, witness records of both witnesses, hourly timestamps and their views
- `examples/` — made-up data signed with example keys, to exercise the verifier and the tools
- `incidents/` — declared incidents (one Markdown file each), with the template and the format guide
- `keys/` — public keys of the logs, of both witnesses and of the time-stamping authorities; the pinned release signers
- `LICENSES/` — the CC BY-ND 4.0 text for the data (the Apache text is `LICENSE`)
- `schemas/` — JSON Schema 2020-12 for every data file
- `tools/` — the standalone verifier, the example generator and the CI scripts (Go)
- `.editorconfig` — editor settings (UTF-8, LF, two spaces; data files untouched)
- `.gitattributes` — LF everywhere, binary types, generated data collapsed in diffs
- `.gitignore` — binaries built from tools/ and editor files
- `CONTRIBUTING.md` — how to contribute and declare an incident, the checks, and the maintainers' settings
- `go.work` — lets `go run ./tools/...` work from the repository root
- `LICENSE` — Apache License 2.0, for code and documentation
- `README.md` — what the record is, where to look, the two witnesses and their regions, what it proves and does not, the layout
- `README.pt-BR.md` — the same in Brazilian Portuguese
- `SECURITY.md` — how to report a vulnerability privately, what is in and out of scope
- `VERIFY.md` — how to check every claim with your own tools, step by step
