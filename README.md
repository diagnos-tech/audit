# diagnos witness record

[![Check](https://github.com/diagnos-tech/audit/actions/workflows/check.yml/badge.svg)](https://github.com/diagnos-tech/audit/actions/workflows/check.yml)
[![Code: Apache-2.0](https://img.shields.io/badge/code-Apache--2.0-blue)](LICENSE)
[![Data: CC0-1.0](https://img.shields.io/badge/data-CC0--1.0-lightgrey)](LICENSES/CC0-1.0.txt)

**Português:** [README.pt-BR.md](README.pt-BR.md)

This repository is the public, independent record of the **witness** that watches diagnos'
transparency logs. Every five minutes the witness reads each log's signed checkpoint, checks that
the log only grew since the last time, cosigns what it saw and commits the result here. Every hour
it has an outside RFC 3161 time-stamping authority date the whole record.

**Live view:** <https://diagnos-tech.github.io/audit/> · **Check it yourself:** [VERIFY.md](VERIFY.md)

The page is a convenience. The record is the files in [`data/v1/`](data/v1), and every claim the
page makes can be checked from them with standard tools, without trusting diagnos, the witness, or
the page.

## What it proves, and what it does not

| It proves | It does not prove |
| --- | --- |
| **Append-only.** Each log only grew: every cosigned checkpoint extends the previous one, by an RFC 9162 consistency proof anyone can recompute, also from the log's own tiles. | **What is in the logs.** Leaves are salted commitments (SHA-256 over a random salt and the canonical record). This repository never holds a leaf, an entry, or any personal data. |
| **One history.** The log showed the witness a single history. A second, conflicting checkpoint signed by the log is cryptographic evidence and is published as a finding. | **Completeness.** That diagnos logged everything it should. A witness sees the log, not the systems that write to it. |
| **When.** Each hour an independent authority signed a hash that covers the latest tree heads and the previous hour, so the past cannot be rewritten without breaking the chain. | **The witness's honesty on its own.** That is why every record carries the log's own signature and a proof you can recheck against the log, and why the hourly tokens come from third parties. |

## The two logs

| Log | What each leaf commits to | Checkpoint origin | Public read URL |
| --- | --- | --- | --- |
| `audit` | one line of the diagnos audit trail | `transparency.diagnos.health/audit/v1` | <https://transparency.diagnos.health/audit/v1/> |
| `signs` | one completed electronic signature | `transparency.diagnos.health/signs/v1` | <https://transparency.diagnos.health/signs/v1/> |

Both are [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) logs with
[signed-note](https://c2sp.org/signed-note) [checkpoints](https://c2sp.org/tlog-checkpoint),
byte-compatible with [Tessera](https://github.com/transparency-dev/tessera). The witness cosigns
with a [tlog-cosignature](https://c2sp.org/tlog-cosignature) (`cosignature/v1`) key named
`witness.diagnos.health/auditor/v1`.

## How often it updates

```
every 5 min   witness reads both checkpoints ──► tree grew? ──► commit: witness record(s)
every hour    witness timestamps the hour    ──────────────────► commit: hourly record + token
              no growth and not the hour     ──────────────────► no commit
```

- A **witness record** appears only when a tree grew, so a quiet log is not a problem.
- An **hourly record** appears every hour, whatever happened, so a record older than about an hour
  and a half means the witness stopped reporting. The page shows this as *stale*.
- The page re-reads `data/v1/latest.json` every four minutes. GitHub Pages caches files for up to
  ten minutes; the page's requests carry a per-minute query string to get past that cache.

## Verify it yourself

You need Go 1.24+, and for the hourly tokens also `openssl`, `jq` and `sha256sum`. The paths below
are illustrative; the page's *How to verify* panel fills in the real ones, and every command also
runs on the example data with `-root examples`.

```sh
git clone --depth 1 https://github.com/diagnos-tech/audit && cd audit

go run ./tools/verify witness data/v1/audit/witness/2026/10/25/140503Z.json   # signatures + proof
go run ./tools/verify consistency data/v1/audit/witness/2026/10/25/140503Z.json  # against the live log
go run ./tools/verify timestamp -openssl data/v1/timestamps/2026/10/25/14Z.json  # hourly token + chain
go run ./tools/verify all -openssl                                               # everything
```

Without a clone, point the verifier at the published site:

```sh
go run github.com/diagnos-tech/audit/tools/verify@latest witness \
  -root https://diagnos-tech.github.io/audit/ data/v1/audit/witness/2026/10/25/140503Z.json
```

The verifier depends only on the Go standard library and `golang.org/x/mod/sumdb/note`, and every
check can also be done by hand. [VERIFY.md](VERIFY.md) walks through each step, says what it proves,
and explains how to pin keys you obtained elsewhere so the check does not rely on this repository.

## Repository layout

| Path | What it holds | Written by |
| --- | --- | --- |
| [`data/v1/<log>/witness/YYYY/MM/DD/HHMMSSZ.json`](schemas/v1/witness.schema.json) | one cosigned checkpoint and the consistency proof from the previous one | witness |
| [`data/v1/<log>/findings/YYYY/MM/DD/HHMMSSZ.json`](schemas/v1/finding.schema.json) | evidence of log misbehaviour (expected to stay empty) | witness |
| [`data/v1/timestamps/YYYY/MM/DD/HHZ.json`](schemas/v1/timestamp.schema.json) | the hour's subject, its imprint and the token's details | witness |
| `data/v1/timestamps/YYYY/MM/DD/HHZ.tsr` | the RFC 3161 `TimeStampResp`, as the authority returned it (DER) | witness |
| [`data/v1/index/YYYY/MM.json`](schemas/v1/index.schema.json) | a light list of the month's records, for the page | witness |
| [`data/v1/latest.json`](schemas/v1/latest.schema.json), [`data/v1/state.json`](schemas/v1/state.schema.json) | the summary the page reads first; the witness's own state | witness |
| [`keys/`](keys) | public keys of the logs and the witness; CA chains of the time-stamping authorities | people |
| [`schemas/v1/`](schemas/v1) | JSON Schema 2020-12 for every data file | people |
| [`tools/`](tools) | the verifier (`tools/verify`), the example generator, CI scripts | people |
| [`index.html`](index.html), [`assets/`](assets) | the page: static HTML, CSS and native ES modules, no build step, no dependencies | people |
| [`examples/`](examples) | example data signed with example keys, for previewing the page; never real records | people |

Dated records are **immutable**: once committed they are never rewritten, because the hourly chain
pins their exact bytes. Only `latest.json`, `state.json` and the current month's index change. CI
rejects any change to a past record.

All data is UTF-8 JSON with two-space indentation and LF line endings (`.gitattributes` keeps it
that way on every platform, which matters because records are pinned by their SHA-256). Times are
RFC 3339 UTC with seconds; tree hashes are base64 as in checkpoints; file digests are lowercase hex
as `sha256sum` prints them.

## Keys and trust

The keys in [`keys/`](keys) let anyone check the records. Checking a record against keys read from
the same repository only shows that the repository is consistent with itself; for an independent
check, compare them with the keys diagnos publishes elsewhere, or keep your own copy and pass it with
`-keys`. [VERIFY.md](VERIFY.md#2-decide-which-keys-to-trust) lists where to look.

## Developing

The data is written by the witness bot; people change code and documentation. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the local preview (`python3 -m http.server`, then
`?data=examples`), the tests and the conventions. The format of every file is shared with the
witness through a contract kept in the diagnos monorepo; the schemas here are its normative form.

## License

- **Code and documentation** (`index.html`, `assets/`, `tools/`, `schemas/`, the Markdown files):
  [Apache License 2.0](LICENSE), like [webtessera](https://github.com/diagnos-tech/webtessera).
  Copyright 2026 MedDeck LTDA.
- **Data** (`data/`, `examples/data/`, `keys/`): dedicated to the public domain under
  [CC0 1.0](LICENSES/CC0-1.0.txt). An integrity record is only useful if anyone can copy, mirror,
  archive and republish it without asking or attributing, and checkpoints and keys are facts; CC0
  removes every condition, including the database rights some jurisdictions would otherwise grant.

## Security

Found a way to make the verifier accept something it should reject, or a record that does not
verify? See [SECURITY.md](SECURITY.md). A failed verification of a real record is exactly what this
repository exists to surface; please report it.
