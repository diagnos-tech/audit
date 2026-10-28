# .github/workflows

Every action is pinned by commit SHA, with its version in a comment. No workflow runs per data commit.

- `check.yml` — on pull requests and code pushes: gofmt, vet, tests, examples, incident files
- `data.yml` — hourly: schemas, verifier and immutability for the commits since the last good run; Mondays: the whole record
- `watchdog.yml` — hourly, no permissions: both doors of the status page, the feeds, freshness of the record, byte-equal copies
