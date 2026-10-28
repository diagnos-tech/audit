# .github/workflows

Every action is pinned by commit SHA, with its version in a comment. No workflow runs per data commit.

- `check.yml` — on pull requests and code pushes: gofmt, vet, staticcheck, tests with the race detector, a short fuzz of the parsers, the examples against the schemas (both versions of the run record) and the verifier, incident files
- `data.yml` — hourly: schemas, verifier (witness records of both witnesses, run records of both versions) and immutability for the commits since the last good run; Mondays: the whole record
- `watchdog.yml` — hourly, no permissions: both doors of the status page, the feeds, freshness of the record, byte-equal copies; quiet until the record has started (latest.json 404 on both copies)
