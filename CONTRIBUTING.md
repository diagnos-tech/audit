# Contributing

Thanks for helping. Two kinds of change happen in this repository, by two kinds of author:

| What | Who | How |
| --- | --- | --- |
| `data/` (run records, views, witness records, hourly records, release evidence) | **only the auditor bot**, `Diagnos Health Bot <tech@diagnos.health>` | direct commits to `develop`, one every 5 minutes |
| everything else: incidents, the verifier, the schemas, the keys, the documents | people | pull requests |

People never edit `data/`. A record is evidence; a hand-edited record is worthless, and CI rejects
any pull request that touches `data/` and any commit that changes an existing record. If the data
looks wrong, open an issue (or see [SECURITY.md](SECURITY.md)).

The status page is not built here: diagnos' own pipeline builds and signs it, and the auditor
publishes it. This repository holds the data the page reads, and the documents, schemas, keys and
verifier that let anyone check it.

## Declaring an incident

Some things cannot be measured from outside, so diagnos declares them. To declare an incident,
open a pull request that adds `incidents/<YYYY-MM-DD>-<slug>.md` with `publish: true`. Copy
[`incidents/2026-10-27-example.md`](incidents/2026-10-27-example.md) and follow
[`incidents/README.md`](incidents/README.md) (the exact format and what each field does to the
colours). In short:

- `categories` is required: `C` (confidentiality: data was exposed), `I` (integrity: something
  changed or ran that should not have), `A` (availability: a service was unusable), one to three
  of them. The incident colours those dimensions of the `services` it lists: `low` and `medium`
  yellow, `high` and `critical` red, combined with the measurements by taking the worse.
  Confidentiality is coloured only by incidents.
- Write the title, the summary and the body in English and in Portuguese.
- The slug must not start with `auto-`: the auditor opens automatic incidents itself (a service
  failing for 15 minutes, an invalid release, a witness finding) and people never write them. To
  explain one, declare an incident with `relates: <its id>`, for example
  `2026-10-01-auto-vault-a-0310`.

Check it before you push:

```sh
go run ./tools/verify incidents incidents/<your-file>.md
```

CI runs the same check on every incident file. Once the pull request is merged the auditor reads the
folder on its next run and the status page shows the incident from `started_at`. To change an
incident, edit its file in a new pull request; do not delete a declaration to hide it, because the
snapshots the auditor keeps pin every version it read.

### Declarar um incidente (pt-BR)

Algumas coisas não podem ser medidas de fora, então a diagnos as declara. Para declarar um
incidente, abra um pull request que adiciona `incidents/<AAAA-MM-DD>-<slug>.md` com
`publish: true`. Copie [`incidents/2026-10-27-example.md`](incidents/2026-10-27-example.md) e siga o
[`incidents/README.md`](incidents/README.md) (em inglês: o formato exato e o que cada campo faz
com as cores). Em resumo:

- `categories` é obrigatório: `C` (confidencialidade: dados foram expostos), `I` (integridade:
  algo mudou ou rodou que não devia), `A` (disponibilidade: um serviço ficou inutilizável), de uma a
  três. O incidente colore essas dimensões dos `services` que ele lista: `low` e `medium` em
  amarelo, `high` e `critical` em vermelho, combinado com as medições pelo pior dos dois. A
  confidencialidade é colorida só por incidentes.
- Escreva título, resumo e corpo em inglês e em português.
- O slug não pode começar com `auto-`: o auditor abre os incidentes automáticos sozinho (um serviço
  falhando por 15 minutos, uma versão inválida, um achado da testemunha) e pessoas nunca os
  escrevem. Para explicar um, declare um incidente com `relates: <id dele>`, por exemplo
  `2026-10-01-auto-vault-a-0310`.

Confira antes de enviar: `go run ./tools/verify incidents incidents/<seu-arquivo>.md`. A CI roda a
mesma conferência em todo arquivo de incidente. Depois do merge o auditor lê a pasta na próxima
execução e a página de status mostra o incidente a partir de `started_at`. Para alterar um incidente,
edite o arquivo em um novo pull request; não apague uma declaração para escondê-la: os snapshots do
auditor fixam todas as versões que ele leu.

## Running the checks locally

Nothing to install but Go 1.24+ (and `openssl` for the token checks):

```sh
go test ./tools/...                         # unit tests, example data, tampering, interop vectors
go run ./tools/verify all -root examples -openssl
go run ./tools/verify incidents incidents/*.md examples/incidents/*.md
tools/ci/validate-json.sh -root examples    # every example file against schemas/v1
go vet ./tools/... && gofmt -l tools        # must print nothing
```

## The example data

[`examples/`](examples) mirrors the repository layout (`examples/data`, `examples/keys`,
`examples/incidents`) with a day of realistic records: two logs with business-hours growth, an hour
when the first authority failed, an hour when every authority failed, an equivocation finding, and
the availability, integrity and confidentiality record of four services over the same period, with
an outage, slow slots, an auditor gap, a published incident and a release that goes from unsigned
to verified, plus 90 days of views. Everything is signed with example keys derived from public
seeds and named under the reserved `.example` domain.

It is generated, deterministically:

```sh
go run ./tools/genexamples
```

`go test ./tools/...` fails if the committed examples differ from what the generator writes, so
regenerate and commit them together with any change to the formats or the generator. Never put
example or test files under `data/`.

## Changing a data format

The formats are shared with the auditor (`apps/auditor` in the diagnos monorepo) through a contract,
`docs/transparency/contract.md` in that repository. The schemas in [`schemas/v1`](schemas/v1) are
its normative form. To change a format:

1. change the contract first and say why;
2. change the schema, `tools/internal/record`, the checks and the generator together;
3. keep it backward compatible (new optional fields only), or start `schemas/v2` and `data/v2`
   alongside: `v1` files are never rewritten.

## Conventions

- **Commits:** small, [Conventional Commits](https://www.conventionalcommits.org) in English
  (`feat(verify): …`, `fix(incidents): …`, `docs: …`, `ci: …`), with a body that says why.
- **Languages:** code, comments, commit messages and `VERIFY.md` are in English, the language of the
  specs and of most people who will audit this. The README has a full Brazilian Portuguese
  translation ([README.pt-BR.md](README.pt-BR.md)): change both together. `VERIFY.md` stays
  single-language on purpose: it is the security-critical procedure, its commands are the same in
  any language, and two copies would drift. Every incident file carries both languages itself.
- **Summary notes:** every folder has a `SUMMARY.md` listing its entries, one line each. Keep it
  accurate when you add, move or remove a file.
- **Go:** standard library plus `golang.org/x/mod` only; `gofmt`; errors that say what was expected.

## Pull requests

Describe what changed and how you checked it (commands run). CI must pass: tests, `go vet`,
`gofmt`, schema validation, `verify all` on the examples and `verify incidents` on every incident
file. A pull request that changes `keys/` or `schemas/` also triggers a check of the whole record.

## For maintainers

Settings that live on GitHub, not in the files. Keep this list in sync with the repository.

- **Pages:** *Settings → Pages → Build and deployment*: source **Deploy from a branch**, branch
  `gh-pages`, folder `/ (root)`. The branch holds only the status page's files and a `.nojekyll`
  (legacy mode: Pages serves the files as they are). **Only the auditor writes `gh-pages`**, when it
  promotes a verified release of the page, so Pages rebuilds when the page changes and never for
  data. Set the custom domain in *Settings → Pages → Custom domain*: `status.diagnos.health`, then
  enable **Enforce HTTPS**.
- **Domain:** in the `diagnos.health` zone, `status` is a DNS-only (not proxied) `CNAME` to
  `diagnos-tech.github.io`, and `_github-pages-challenge-diagnos-tech` is the verification `TXT`
  (both in the monorepo's Terraform). **Verify the domain for the organization** (*Organization
  settings → Pages → Add a domain*): it prevents another account from claiming it.
  `audit.diagnos.health` and the root of `transparency.diagnos.health` are Cloudflare redirects to
  the status page; this repository does not serve them.
- **Ruleset for `develop`** (*Settings → Rules → Rulesets*), with no bypass for the first three:
  block force pushes, block deletions, require linear history. The record is the history; nobody,
  the bot included, may rewrite it. Then require a pull request and the status check
  **Tools, schemas and examples** for everyone except the auditor bot, which pushes directly. If the
  organization's plan has push rulesets, also restrict `data/**` to the bot and `keys/**`,
  `schemas/**` and `incidents/**` to pull requests. A second ruleset for `gh-pages` allows only the
  bot to push and blocks force pushes and deletion.
- **The bot:** a GitHub App installed only on this repository with *Contents: read and write* (no
  other permission) is preferred to a personal token or a deploy key; commits made through the API
  with an App are signed by GitHub, which allows **Require signed commits** in the ruleset. Its
  commits are authored as `Diagnos Health Bot <tech@diagnos.health>`.
- **Workflows:** no workflow runs per data commit (there is one every five minutes).
  [`data.yml`](.github/workflows/data.yml) runs hourly and verifies the commits since its last
  successful run (its base is read from `gh run list`, so the workflow has `actions: read`), every
  Monday the whole record with `-complete`, and on demand (`full`); a pull request must not touch
  `data/` at all. [`watchdog.yml`](.github/workflows/watchdog.yml) runs hourly with no permissions
  at all (`curl` and `jq`) and fails, so GitHub e-mails the repository's owner (keep that
  notification on), unless: both doors of the status page answer `/healthz`; the feeds
  (`feeds/incidents.*`, `feeds/all.*`) are well-shaped on the status page and on the bucket;
  `data/v1/cia/latest.json` is under 20 minutes old on the bucket and on GitHub raw; and three random
  run records older than two hours are byte-equal on both. Its URLs are in one `env:` block, and the
  production bucket name there is `TODO(gustavo)` until confirmed.
- **Signing identity:** `keys/signers.json` pins the identity whose signature a release needs: for
  every service (`frontend`, `vault`, `sign`, `status`), diagnos' monorepo, `pipeline.yml`, branch
  `main`, by repository and owner id. Renaming the workflow or the branch, or moving the monorepo,
  changes what a valid signature is: update `keys/signers.json` and the auditor's configuration
  (`monorepo_signer` in the monorepo's Terraform) in the same change, or the services turn yellow
  or red on the page.
- **Schema ids:** the `$id` of every schema stays `https://diagnos-tech.github.io/audit/schemas/…`.
  They are identifiers, not addresses: the validators map them to the files in `schemas/v1`
  (see `tools/ci/validate-json.sh`), and changing the ids would change every `$ref`.
- **Actions:** allow GitHub-owned actions and `sigstore/cosign-installer`, all pinned by commit
  (Dependabot keeps the pins current). Default workflow permissions *read*; do not let Actions
  create or approve pull requests.
- **Security:** enable private vulnerability reporting (SECURITY.md links to it), secret scanning with
  push protection, and Dependabot (`.github/dependabot.yml`).
- **Launch:** before the auditor's first push, add `keys/logs/audit.vkey`, `keys/logs/signs.vkey`
  and `keys/witness/auditor.vkey` in a reviewed pull request (see [keys/README.md](keys/README.md)),
  and publish the same keys outside GitHub. The authorities' roots (`keys/tsa/`) and the signers
  (`keys/signers.json`) are already in.
