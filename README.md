# diagnos audit record

[![Check](https://github.com/diagnos-tech/audit/actions/workflows/check.yml/badge.svg)](https://github.com/diagnos-tech/audit/actions/workflows/check.yml)
[![Data](https://github.com/diagnos-tech/audit/actions/workflows/data.yml/badge.svg)](https://github.com/diagnos-tech/audit/actions/workflows/data.yml)
[![Code: Apache-2.0](https://img.shields.io/badge/code-Apache--2.0-blue)](LICENSE)
[![Data: CC BY-ND 4.0](https://img.shields.io/badge/data-CC_BY--ND_4.0-lightgrey)](LICENSES/CC-BY-ND-4.0.txt)

**Português:** [README.pt-BR.md](README.pt-BR.md)

This repository is the public, independent record of the **confidentiality, integrity and
availability** of diagnos. Every five minutes the diagnos auditor checks four services, reads the
incidents diagnos has declared, witnesses diagnos' transparency logs, publishes the result to a public
Scaleway bucket and **commits the same files here, to `develop`, on every run**. The services are
measured from two regions, Europe and Latin America, by two independent witnesses. Every hour an
outside RFC 3161 time-stamping authority dates the whole record.

People change only a few things here: they declare incidents by pull request, and they change the
documents, schemas, keys and the verifier. Everything under `data/` is written by the auditor.

## Where to look

| What | Address |
| --- | --- |
| **The status page** | <https://status.diagnos.health/> |
| If that page does not load: the same page, served by Scaleway | <https://imgexam-auditor-production.s3-website.fr-par.scw.cloud/> |
| The record, on GitHub | this repository, or <https://raw.githubusercontent.com/diagnos-tech/audit/develop/> |
| The record, on Scaleway | <https://imgexam-auditor-production.s3.fr-par.scw.cloud/> |
| Changes as they happen | [feeds](#feeds-and-subscriptions) under <https://status.diagnos.health/feeds/> |
| Check it yourself | [VERIFY.md](VERIFY.md) |

`audit.diagnos.health` and the root of `transparency.diagnos.health` redirect to the status page. The
page is built and signed by diagnos' own pipeline and published by the auditor only after it has
verified the build; this repository holds only its data. The page is a convenience: the record is the
files in [`data/v1/`](data/v1) and [`incidents/`](incidents), and every claim the page makes can be
checked from them with standard tools, without trusting diagnos, the auditor, or the page.

## The three dimensions

| Dimension | What is checked, every five minutes | Colour on the page |
| --- | --- | --- |
| **Availability** | `GET /healthz` of each service answers 200 with a well-formed body, in time, over a valid TLS certificate, from Europe and from Latin America; the transparency logs' checkpoints are readable | green: answered normally · yellow: slow, certificate expiring, or reachable from one region only · red: no valid answer |
| **Integrity** | the release each service says it runs was signed by diagnos' CI workflow (Sigstore) with SLSA provenance, and the files it serves match the signed manifest; also that the witnessed transparency logs only grew | green: verified · yellow: cannot be confirmed (no evidence, verification pending) · red: evidence invalid or bytes differ |
| **Confidentiality** | the incidents diagnos has declared in [`incidents/`](incidents) that affect the service at that time; nothing else colours it | green: none declared · yellow: low or medium · red: high or critical |

Grey means *not measured*: the auditor did not run, or the service could not be reached (see
[late data is never an outage](#late-data-is-never-an-outage)). Incidents colour availability and
integrity too (see [incidents](#incidents)). The
services are `diagnos.health` (website and app), `vault.diagnos.health` (the API that keeps the
encrypted exams), `sign.diagnos.health` (document signing) and `status.diagnos.health` (the status
page itself: static, served on GitHub Pages and on its Scaleway copy).

## Two witnesses, two regions

The services are measured from two places at once, each by its own **witness** with its own key.
A region on the page is a witness; the record never shows a witness's id without its name.

| Witness (id) | Region on the page | Runs on | Key |
| --- | --- | --- | --- |
| `europe` | Europe | Scaleway, Paris. It is the only clock and the only witness that publishes: the one run record per slot is its. | [`keys/witness/auditor.vkey`](keys/README.md) |
| `latam` | Latin America | Oracle Cloud, São Paulo. It has no clock and publishes nothing; when asked, it measures from where it is, signs what it measured and answers. | [`keys/witness/latam.vkey`](keys/README.md) |

Each witness signs its own measurement, so a number from Latin America can be checked against
Latin America's key and not against diagnos' say-so. The run record holds both signed
measurements, and next to them the **combined** result of each service, which the verifier
recomputes from them. The combination follows four rules:

- **Red (down) only when the witnesses agree.** Both fail in the same slot, or only one witness
  measured and its own retry confirms the failure.
- **Amber, `regional`, when one fails and the other does not.** The service is reachable from one
  region and not the other; the page names the region. It is never red on its own.
- **A silent witness is neutral.** If a witness did not answer, did not verify, or ran out of time,
  its measurement is *not measured* (grey) for that slot and the other witness decides alone.
  That is never an outage of a service; after three runs in a row the change stream says that the
  witness's measurements are unavailable, and after two good runs that they are back.
- **Evidence is not a vote.** A finding or a halt on a transparency log, seen by either witness,
  counts: showing one region a different tree than the other is exactly the attack a second witness
  is there to catch. When both witnesses read two different roots for the same size of a log, the
  log signed two trees and the record must say so.

For each service and region a day file keeps the slots' colours and the latency of every successful
probe (288 values, so any percentile can be recomputed), with the minimum (p0), p50, p75, p90, p95,
p99, the maximum (p100), the mean and the number of samples. Percentiles are *nearest rank* over the
probes that succeeded: a timeout is an error, counted by its class (name lookup, connection,
handshake, timeout, 5xx, 4xx, assertion), never a very slow answer. The time of each probe is split
into lookup, connection, handshake, wait and transfer.

The key of the second witness is published later, by a reviewed pull request. Until it exists the
verifier treats it as absent, not as wrong: everything else about the second witness's records is
checked and the report says that their signatures were not, with a warning. A key file that exists
and is wrong is a failure.

## What it proves, and what it does not

| | It proves | It does not prove |
| --- | --- | --- |
| **Availability** | Every five minutes, from two independent places (Scaleway in Paris and Oracle Cloud in São Paulo), each service's `/healthz` answered 200 with a well-formed, correctly identified body, within the latency budget, over a valid TLS certificate, or how it failed. A failure seen from one region only is shown as such. Gaps in the record are visible as grey. | That every user could reach the service (two vantage points are not every network; a problem of one provider or one country elsewhere can be invisible). That features behind `/healthz` work (it touches no database, by design). Anything between two probes: an outage shorter than five minutes can be missed. That the transparency logs accept writes (only that their checkpoints are readable). |
| **Integrity** | The release each service says it runs was built by a pinned CI workflow, on a pinned branch of a pinned repository (by numeric id), from the commit it names: the release manifest is signed through Sigstore and an SLSA provenance attestation for the same digest was signed by the same identity. For static content (diagnos.health, the status page, the Workers' static assets) the bytes actually served were sampled and match the signed manifest. | That a Worker (vault, sign) runs the script it reports: the auditor cannot read Workers' code. That the source is free of bugs or backdoors. That the CI itself was not compromised (SLSA Build Level 2, not 3). That a static file changed between two samples was noticed at once: a full pass over the manifest takes from tens of minutes to many hours, depending on its size. |
| **Confidentiality** | Which incidents diagnos has declared, against which services, with what severity and timeline. Each snapshot pins the Git blob of every incident file and is chained into the hourly timestamps, so a later edit or deletion of a declaration stays visible. | That nothing else happened. The auditor cannot detect a leak: a green row means *no incident declared*, nothing more. Declaring is a commitment diagnos makes in public; this record makes breaking it later visible, not impossible. |
| **Witness** | Each transparency log only grew: every cosigned checkpoint extends the previous one, by an RFC 9162 consistency proof anyone can recompute, also from the log's own tiles. The log showed the witness one history (a second, conflicting checkpoint is published as a finding). Each hour an independent authority signed a hash covering the latest tree heads, the previous hour and the latest run record, so the past cannot be rewritten without breaking the chain. | What is in the logs: leaves are salted commitments, and this repository never holds a leaf, an entry or personal data. That diagnos logged everything it should: a witness sees the log, not the systems that write to it. |

The auditor is operated by diagnos. What gives the record independence is the third-party RFC 3161
timestamps every hour (which also pin the chain of run records), Sigstore's public logs for
releases, the public Git history of this repository, and the second copy of the record in the public
bucket: an hourly check compares sample records of the two copies byte for byte, and a difference
is a failure to explain.

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
every 5 min   probe 4 services, check releases, read incidents, witness both logs
              ──► publish to the public bucket ──► commit the same files to develop
every hour    timestamp the hour (also pins the latest run record)
              ──► hourly record + RFC 3161 token, in the same commit
```

- A **run record** is written for every five-minute slot, whatever the result, so a missing slot
  means the auditor did not run: the page shows it as grey, never as green.
- A **witness record** appears only when a tree grew, so a quiet log is not a problem.
- An **hourly record** appears every hour, whatever happened.
- A **change event** (a service entering a new level, an incident opened, updated or resolved, a
  new verified release, a witness finding, the record delayed or resumed) is added to
  `data/v1/cia/changes.json` and to the [feeds](#feeds-and-subscriptions) when it happens; the feeds
  are not rewritten otherwise.
- **No workflow runs per commit.** [`data.yml`](.github/workflows/data.yml) runs once an hour and
  verifies every commit since its last successful run, and every Monday the whole record.
  [`watchdog.yml`](.github/workflows/watchdog.yml) runs once an hour and fails, so GitHub e-mails the
  owner, unless both doors of the status page answer, the record is less than 20 minutes old on both
  copies, and sample run records are byte-for-byte equal on both.

## Incidents

Every incident has **categories**: `C` confidentiality (data was exposed), `I` integrity (something
changed or ran that should not have) and `A` availability (a service was unusable). An incident
colours those dimensions of the services it lists, from when it started until it was resolved:
`low` and `medium` yellow, `high` and `critical` red, and it is combined with the measurements by
taking the worse of the two. Confidentiality is coloured only by incidents: nothing can measure a
leak from outside.

- **Declared incidents** are Markdown files in [`incidents/`](incidents), added by a reviewed pull
  request. [`incidents/README.md`](incidents/README.md) has the format and what each field does to
  the colours; [CONTRIBUTING.md](CONTRIBUTING.md) has the workflow.
- **Automatic incidents** are opened, updated and resolved by the auditor, never by people: an
  availability incident when a service fails for 3 consecutive five-minute slots, an integrity
  incident for an invalid release, served files that differ from the signed manifest, or a witness
  finding. A confidentiality incident is never automatic. Each change is an immutable record under
  `data/v1/cia/incidents/events/`, and the incident appears in `data/v1/cia/incidents.json` next
  to the declared ones. To explain an automatic incident, declare one with `relates: <its id>` (a
  postmortem).

## Late data is never an outage

A delay or a gap in the record is shown neutral and never counted as downtime: a slot with no
record is *not measured* (`none`, a grey hatched mark), and the change stream says *record
delayed*, never *down*.

The auditor also protects itself from false reds. Every run makes a control probe to a host
outside diagnos. If the control probe and every service fail in the same run, the auditor's own
network failed, not the services: the run is a **vantage failure**. All its network checks are
recorded as `none` with the code `vantage` (not `fail`), no incident is opened, and the change
stream says the auditor's network failed. `tools/verify cia` rejects a record in which every
service failed while the control probe failed (it had to be recorded as a vantage failure) and a
record whose `vantage` checks are inconsistent.

The same goes for each witness on its own: a witness whose control probe failed measured nothing,
and a witness that is silent is not measuring, which makes its region grey and the other region
decide. Neither is ever counted as an outage.

## Feeds and subscriptions

Every change event is published as a feed (the last 100 events of each), in RSS 2.0, Atom and JSON
Feed 1.1:

| Feed | What |
| --- | --- |
| `feeds/all.rss`, `feeds/all.atom`, `feeds/all.json` | every change |
| `feeds/<service>.rss`, `.atom`, `.json` for `frontend`, `vault`, `sign`, `status` | changes of one service |
| `feeds/incidents.rss`, `.atom`, `.json` | incidents only, declared and automatic |

They are served from <https://status.diagnos.health/feeds/> and from
<https://imgexam-auditor-production.s3.fr-par.scw.cloud/feeds/>; they live on the status page and the
bucket, not in this repository. They are a convenience for subscribers: the record is the files in
[`data/v1/`](data/v1). Each feed declares a
[WebSub](https://www.w3.org/TR/websub/) hub, so readers that support it get a change at once; the
others poll the static files.

- **Any feed reader:** add the feed's address.
- **Slack:** with Slack's RSS app, `/feed subscribe https://status.diagnos.health/feeds/all.rss`.
- **Microsoft Teams:** the RSS connector, or a Workflows flow that runs when a feed item is
  published.
- **E-mail:** through a feed-to-email service such as Blogtrottr or Feedrabbit. These are third
  parties that diagnos does not run.

diagnos does not provide e-mail or webhook subscriptions.

## Verify it yourself

You need Go 1.24+; for the hourly tokens also `openssl`, `jq` and `sha256sum`; for releases also
[`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/). The paths below are
illustrative, and every command except the release check also runs on the example data with
`-root examples`.

```sh
git clone --depth 1 https://github.com/diagnos-tech/audit && cd audit

go run ./tools/verify cia                                                 # run records, incidents, views
go run ./tools/verify release -cosign data/v1/cia/releases/vault/<digest> # a release, with cosign
go run ./tools/verify incidents incidents/*.md                            # declarations follow the format
go run ./tools/verify witness data/v1/audit/witness/2026/10/25/140503Z.json  # signatures + proof
go run ./tools/verify timestamp -openssl data/v1/timestamps/2026/10/25/14Z.json  # hourly token + chain
go run ./tools/verify all -openssl -cosign                                # everything
```

Without a clone, point the verifier at the files on GitHub:

```sh
go run github.com/diagnos-tech/audit/tools/verify@latest witness \
  -root https://raw.githubusercontent.com/diagnos-tech/audit/develop/ \
  data/v1/audit/witness/2026/10/25/140503Z.json
```

Remote mode works for a single record you name (`witness`, `timestamp`, `finding`, `consistency`,
`release`). It cannot list files, so `cia` and `all`, which read the whole record, need a clone.

The verifier depends only on the Go standard library and `golang.org/x/mod/sumdb/note`; releases are
checked with the `cosign` you install, and every check can also be done by hand.
[VERIFY.md](VERIFY.md) walks through each step, says what it proves, and explains how to pin keys
you obtained elsewhere so the check does not rely on this repository.

## Repository layout

| Path | What it holds | Written by |
| --- | --- | --- |
| [`data/v1/cia/runs/YYYY/MM/DD/HHMMZ.json`](schemas/v1/cia-run.schema.json) | one five-minute run: per service and dimension, the level and every check with its code, chained to the previous run. `cia-run/v1` is the single-vantage record; [`cia-run/v2`](schemas/v1/cia-run-v2.schema.json) holds each witness's signed measurement and the combined result. Both live here, in one chain | auditor |
| [`data/v1/cia/incidents/YYYY/MM/DD/HHMMZ.json`](schemas/v1/cia-incidents.schema.json) | a snapshot of the declared incidents, written when they change | auditor |
| [`data/v1/cia/incidents/events/YYYY/MM/DD/<id>-<seq>.json`](schemas/v1/cia-incident-event.schema.json) | one change of an automatic incident: opened, updated or resolved | auditor |
| [`data/v1/cia/releases/<service>/<digest>/`](schemas/v1/cia-release.schema.json) | the verdict on one release and the evidence it was judged on: manifest, Sigstore signature, provenance | auditor |
| [`data/v1/cia/days/YYYY/MM/DD.json`](schemas/v1/cia-day.schema.json) | a view: one letter per five-minute slot and per dimension (incidents included), the spans that are not green, the day's latency | auditor |
| [`data/v1/cia/latest.json`](schemas/v1/cia-latest.schema.json), [`summary.json`](schemas/v1/cia-summary.schema.json), [`incidents.json`](schemas/v1/cia-incident-list.schema.json), [`changes.json`](schemas/v1/cia-changes.schema.json), [`changes-recent.json`](schemas/v1/cia-changes-recent.schema.json) | views: the headline, the 90-day summary, the incidents (declared and automatic) in one list, the last 500 change events, and the newest 30 of them | auditor |
| [`data/v1/sync.json`](schemas/v1/sync.schema.json) | how far the auditor's private journal has been mirrored here | auditor |
| [`data/v1/<log>/witness/YYYY/MM/DD/HHMMSSZ.json`](schemas/v1/witness.schema.json) | one cosigned checkpoint and the consistency proof from the previous one | auditor |
| [`data/v1/<log>/findings/YYYY/MM/DD/HHMMSSZ.json`](schemas/v1/finding.schema.json) | evidence of log misbehaviour (expected to stay empty) | auditor |
| `data/v1/witnesses/latam/<log>/witness/…` and `…/findings/…` | the same two kinds of file for the second witness (Latin America), cosigned with its own key and chained on its own; the primary witness's files stay where they have always been | auditor |
| [`data/v1/timestamps/YYYY/MM/DD/HHZ.json`](schemas/v1/timestamp.schema.json) | the hour's subject, its imprint and the token's details | auditor |
| `data/v1/timestamps/YYYY/MM/DD/HHZ.tsr` | the RFC 3161 `TimeStampResp`, as the authority returned it (DER) | auditor |
| [`data/v1/index/YYYY/MM.json`](schemas/v1/index.schema.json) | a light list of the month's witness records | auditor |
| [`data/v1/latest.json`](schemas/v1/latest.schema.json), [`data/v1/state.json`](schemas/v1/state.schema.json) | the witness summary; the witness's own state | auditor |
| [`incidents/`](incidents) | declared incidents, one Markdown file each, and the template (automatic incidents are never files here) | people, by pull request |
| [`keys/`](keys) | public keys of the logs and of each witness (`witness/auditor.vkey`, and `witness/latam.vkey` once it is published); CA chains of the time-stamping authorities; [`signers.json`](keys/signers.json), the CI identity each service's releases must be signed by | people, by pull request |
| [`schemas/v1/`](schemas/v1) | JSON Schema 2020-12 for every data file | people, by pull request |
| [`tools/verify`](tools/verify) and the packages it uses | the standalone verifier | people |
| [`tools/genexamples`](tools/genexamples), [`tools/ci`](tools/ci) | the example generator and the CI scripts | people |
| [`examples/`](examples) | example data signed with example keys; never real records | people |
| [`.github/workflows/`](.github/workflows) | `check` (code and examples), `data` (the record, hourly), `watchdog` (the doors and the copies, hourly) | people |
| `README.md`, `VERIFY.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`, `LICENSES/` | the documents | people |

**Records are immutable; views are not.** Run records, incident snapshots and events, release
evidence, witness records, findings and hourly records are never rewritten: the hourly chain pins
their exact bytes, and `data.yml` rejects any change to one. Only the *views* change: `latest.json`,
`state.json`, `index/**`, `sync.json` and `cia/latest.json`, `cia/summary.json`,
`cia/incidents.json`, `cia/changes.json`, `cia/changes-recent.json` and `cia/days/**`. Each view is a pure function of the records, and
`tools/verify cia` recomputes them all and compares, so a view cannot say anything the records do not.

All data is UTF-8 JSON with LF line endings (`.gitattributes` keeps it that way on every platform,
which matters because records are pinned by their SHA-256). Records are indented by two spaces, so
that people can read them on GitHub. Views are written on one line, because the servers that serve
them do not compress and an indented array costs a line per number; readers parse either, and the
verifier compares what a file says, not how it is laid out. Times are
RFC 3339 UTC with seconds; tree hashes are base64 as in checkpoints; file digests are lowercase hex
as `sha256sum` prints them.

## Keys and trust

The keys in [`keys/`](keys) let anyone check the records, each witness's included. Checking a record against keys read from
the same repository only shows that the repository is consistent with itself; for an independent
check, compare them with the keys diagnos publishes elsewhere, or keep your own copy and pass it with
`-keys`. [VERIFY.md](VERIFY.md#2-decide-which-keys-to-trust) lists where to look.
[`keys/signers.json`](keys/signers.json) pins, for each service, the GitHub repository (by numeric
id), workflow and branch whose signature a release must carry.

## Developing

The data is written by the auditor bot; people change incidents, documents, schemas, keys and the
verifier. See [CONTRIBUTING.md](CONTRIBUTING.md) for the tests and the conventions. The format of
every file is shared with the auditor through a contract kept in the diagnos monorepo; the schemas
here are its normative form.

## License

- **Code and documentation** (`tools/`, `schemas/`, the Markdown files):
  [Apache License 2.0](LICENSE), like [webtessera](https://github.com/diagnos-tech/webtessera).
  Copyright 2026 MedDeck LTDA.
- **Data** (`data/`, `examples/data/`, `keys/`): licensed under
  [CC BY-ND 4.0](LICENSES/CC-BY-ND-4.0.txt). Anyone may copy, mirror, archive and republish the
  record, in whole or in part and for any purpose, as long as it stays unchanged and is credited as
  "diagnos audit record, © 2026 MedDeck LTDA, CC BY-ND 4.0" with a link to this repository. Altered
  copies may not be shared: a record that was edited is no longer the record the signatures cover.
  The license also covers the database rights some jurisdictions grant.

## Security

Found a way to make the verifier accept something it should reject, a release the auditor accepted
that `cosign` rejects, two copies of the record that disagree, or a record that does not verify?
See [SECURITY.md](SECURITY.md). A failed verification of a real record is exactly what this
repository exists to surface; please report it.
