# Contributing

Thanks for helping. Two kinds of change happen in this repository, by two kinds of author:

| What | Who | How |
| --- | --- | --- |
| `data/` (records, indexes, `latest.json`, `state.json`) | **only the witness bot**, `Diagnos Health Bot <tech@diagnos.health>` | direct commits, every 5 minutes when a log grows and every hour |
| everything else: the page, the tools, the schemas, the docs, `keys/` | people | pull requests |

People never edit `data/`. A record is evidence; a hand-edited record is worthless and CI rejects any
change to an existing one. If the data looks wrong, open an issue (or see [SECURITY.md](SECURITY.md)).

## Running it locally

There is no build step and nothing to install for the page. Serve the folder over HTTP (browsers do
not let a page opened from disk read its data files):

```sh
python3 -m http.server 8000
# real data:     http://localhost:8000/
# example data:  http://localhost:8000/?data=examples
```

Until the witness publishes its first record, the real view says *Nothing published yet*; use the
examples. In the example data set the clock is pinned a few minutes after its last commit; add
`&now=2026-10-01T18:00:00Z` (any RFC 3339 time) to preview other states, such as a stale witness.
`?data=` accepts only the names in `assets/config.js` (`DATA_SETS`), so a link cannot make the page
show data from elsewhere.

The tools need Go 1.24+ (and `openssl` for the token checks):

```sh
go test ./tools/...                         # unit tests, example data, tampering, interop vectors
go run ./tools/verify all -root examples -openssl
tools/ci/validate-json.sh -root examples    # every example file against schemas/v1
go vet ./tools/... && gofmt -l tools        # must print nothing
```

## The example data

[`examples/`](examples) mirrors the repository layout (`examples/data`, `examples/keys`) with a
day of realistic records: two logs with business-hours growth, an hour when the first authority
failed, an hour when every authority failed, and an equivocation finding. Everything is signed with
example keys derived from public seeds and named under the reserved `.example` domain.

It is generated, deterministically:

```sh
go run ./tools/genexamples
```

`go test ./tools/...` fails if the committed examples differ from what the generator writes, so
regenerate and commit them together with any change to the formats or the generator. Never put
example or test files under `data/`.

## Changing a data format

The formats are shared with the witness (`apps/auditor` in the diagnos monorepo) through a contract,
`docs/transparency/contract.md` in that repository. The schemas in [`schemas/v1`](schemas/v1) are its
normative form. To change a format:

1. change the contract first and say why;
2. change the schema, `tools/internal/record`, the checks, the generator and the page together;
3. keep it backward compatible (new optional fields only), or start `schemas/v2` and `data/v2`
   alongside: `v1` files are never rewritten.

## Conventions

- **Commits:** small, [Conventional Commits](https://www.conventionalcommits.org) in English
  (`feat(site): …`, `fix(verify): …`, `docs: …`, `ci: …`), with a body that says why.
- **Languages:** code, comments, commit messages and `VERIFY.md` are in English, the language of the
  specs and of most people who will audit this. The README has a full Brazilian Portuguese
  translation ([README.pt-BR.md](README.pt-BR.md)) and the page is bilingual (`assets/i18n.js`): add
  every new string in both languages. `VERIFY.md` stays single-language on purpose: it is the
  security-critical procedure, its commands are the same in any language, and two copies would
  drift.
- **The page:** native ES modules, no framework, no bundler, no third-party code, no inline scripts
  or styles (the CSP forbids them). Data reaches the DOM only as text (`assets/dom.js`); values that
  end up in links or commands are checked against patterns first (`assets/data.js`). Keep files
  small and the total JS and CSS small enough to read in one sitting.
- **Accessibility (WCAG 2.2 AA):** semantic landmarks and headings, a visible `:focus-visible` ring,
  keyboard operation everywhere, state never by colour alone (every status has an icon and a word),
  contrast at least 4.5:1 for text and 3:1 for controls in both colour schemes, one polite live
  region for refresh news, and layouts that work at 320 px wide.
- **Go:** standard library plus `golang.org/x/mod` only; `gofmt`; errors that say what was expected.

## Pull requests

Describe what changed and how you checked it (commands run, browsers and screen sizes tried). CI
must pass: tests, `go vet`, `gofmt`, schema validation and `verify all` on the examples.

## For maintainers

Settings that live on GitHub, not in the files. Keep this list in sync with the repository.

- **Pages:** *Settings → Pages → Build and deployment*: source **Deploy from a branch**, branch
  `develop`, folder `/ (root)`. `.nojekyll` makes Pages serve the files as they are. For a custom
  domain, add it there, point a `CNAME` record at `diagnos-tech.github.io`, verify the domain in the
  organization settings (prevents takeover), enable **Enforce HTTPS**, and update `SITE` in
  `assets/config.js` and the `-root` URLs in the docs.
- **Ruleset for `develop`** (*Settings → Rules → Rulesets*), with no bypass for the first three:
  block force pushes, block deletions, require linear history. The record is the history; nobody,
  the bot included, may rewrite it. Then require a pull request and the status check
  **Tools, schemas and examples** for everyone except the witness bot, which pushes directly. If the
  organization's plan has push rulesets, also restrict `data/**` to the bot and `keys/**` and
  `schemas/**` to pull requests.
- **The bot:** a GitHub App installed only on this repository with *Contents: read and write* (no
  other permission) is preferred to a personal token or a deploy key; commits made through the API
  with an App are signed by GitHub, which allows **Require signed commits** in the ruleset. Its
  commits are authored as `Diagnos Health Bot <tech@diagnos.health>`.
- **Actions:** allow only GitHub-owned actions (the workflows use `actions/checkout` and
  `actions/setup-go`, pinned by commit), default workflow permissions *read*, and do not let Actions
  create or approve pull requests.
- **Security:** enable private vulnerability reporting (SECURITY.md links to it), secret scanning with
  push protection, and Dependabot (`.github/dependabot.yml`).
- **Launch:** before the witness's first push, add `keys/logs/audit.vkey`, `keys/logs/signs.vkey`
  and `keys/witness/auditor.vkey` in a reviewed pull request (see [keys/README.md](keys/README.md)),
  and publish the same keys outside GitHub. The authorities' roots (`keys/tsa/`) are already in.
