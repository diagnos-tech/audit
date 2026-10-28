# Verifying the audit record

This is how to check, with your own tools, everything the record and the status page claim. Nothing
here asks you to trust diagnos, the auditor, the status page or this repository's CI. Each step says
what it proves and what it does not.

The record has two parts. The **witness** part (sections 3 to 6) checks diagnos' transparency logs
and dates the record every hour. The **availability, integrity and confidentiality** part (sections
10 to 12) checks the four services every five minutes: run records and the views built from them,
the signed releases of the services, and the incidents diagnos declared. Since the services are
measured from two regions by two independent witnesses, section 13 explains how to check what each
witness signed and how the two are combined.

**Try every command on the example data first:** run them from `examples/` (or add `-root examples`
to the `go run` commands). The examples are signed with published example keys and include an
hour when one authority failed, an hour when every authority failed, and one finding, so you can see
every outcome (the release check with `-cosign` needs a real release: the examples carry no real
Sigstore bundle). Paths below are examples too; use the ones of the record you are checking.

1. [Get the record](#1-get-the-record)
2. [Decide which keys to trust](#2-decide-which-keys-to-trust)
3. [Verify a witness record](#3-verify-a-witness-record)
4. [Verify against the log itself](#4-verify-against-the-log-itself)
5. [Verify the hourly timestamps](#5-verify-the-hourly-timestamps)
6. [Verify a finding](#6-verify-a-finding)
7. [Verify everything at once](#7-verify-everything-at-once)
8. [When something does not verify](#8-when-something-does-not-verify)
9. [Reference: the formats](#9-reference-the-formats)
10. [Verify the run records and the views](#10-verify-the-run-records-and-the-views)
11. [Verify a release with cosign](#11-verify-a-release-with-cosign)
12. [Verify the declared incidents](#12-verify-the-declared-incidents)
13. [Verify the two witnesses](#13-verify-the-two-witnesses)

## What you need

| Tool | For | Notes |
| --- | --- | --- |
| Go 1.24 or later | `tools/verify` | Its only dependency is `golang.org/x/mod`, fetched through the Go checksum database. |
| OpenSSL 1.1.1 or later | RFC 3161 tokens, and Ed25519 by hand | `openssl version` |
| [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 3.x | releases (sections 10 and 11), `-cosign` | `cosign version`; only for the release checks |
| `jq`, `sha256sum`, `base64`, `xxd`, `awk` | recomputing hashes by hand | coreutils / standard packages |

## 1. Get the record

```sh
git clone --depth 1 https://github.com/diagnos-tech/audit
cd audit
```

A shallow clone is enough for any single record and its neighbours. `verify all` reads every file,
so it needs a full checkout of `data/` (still a shallow history).

Without cloning, point `-root` at the files on GitHub. This works for a single record you name
(`witness`, `timestamp`, `finding`, `consistency`, `release`):

```sh
go run github.com/diagnos-tech/audit/tools/verify@latest witness \
  -root https://raw.githubusercontent.com/diagnos-tech/audit/develop/ \
  data/v1/audit/witness/2026/10/25/140503Z.json
```

Remote mode cannot list files, so `cia` and `all`, which read the whole record, need a clone. The
same bytes are in the public Scaleway bucket
(`https://imgexam-auditor-production.s3.fr-par.scw.cloud/`); an hourly check compares the two
copies, and you can too.

Records never change once committed, so a copy you keep stays checkable forever, and keeping one is
itself a check: if a later copy of the repository disagrees with yours, the history was rewritten.

## 2. Decide which keys to trust

Every witness check depends on three kinds of public key, all in [`keys/`](keys), and the release
checks on a fourth, the pinned signers:

| File | Key | Format |
| --- | --- | --- |
| `keys/logs/audit.vkey`, `keys/logs/signs.vkey` | each log's checkpoint key | signed-note verifier key, Ed25519 (`0x01`) |
| `keys/witness/auditor.vkey` | the primary witness's (Europe) cosignature key | `cosignature/v1` verifier key (`0x04`) |
| `keys/witness/latam.vkey` | the second witness's (Latin America) cosignature key; added by a reviewed pull request once the second witness is live | `cosignature/v1` verifier key (`0x04`) |
| `keys/tsa/<provider>.pem` | the CA chain of each time-stamping authority | PEM certificates; see [keys/tsa/README.md](keys/tsa/README.md) |
| `keys/signers.json` | for each service, the CI identity whose signature a release must carry | `signers/v1`; used in sections 10 and 11, see [keys/README.md](keys/README.md) |

Until `keys/witness/latam.vkey` exists the verifier treats the second witness's key as absent, which
is not a failure: it checks everything else about the second witness's records and says, with a
warning, that their signatures were not checked. A key file that exists and does not match is a
failure. The primary witness's key is never optional.

A verifier key reads `<name>+<key hash>+<base64(algorithm byte ‖ 32-byte public key)>`. Its key hash
is not decoration: it is the first four bytes of `SHA-256(name ‖ "\n" ‖ algorithm ‖ key)`, and you
can recompute it:

```sh
K=keys/logs/audit.vkey
{ printf '%s\n' "$(cut -d+ -f1 $K)"; cut -d+ -f3- $K | base64 -d; } | sha256sum | head -c 8; echo
cut -d+ -f2 $K   # must print the same eight hex digits
```

**Keys read from this repository only prove that the repository agrees with itself.** Someone able
to rewrite the repository could rewrite the keys too. For an independent check, compare the keys
with copies you obtained some other way and keep them:

- the log keys are the keys the logs themselves sign with: fetch
  `https://transparency.diagnos.health/audit/v1/checkpoint` and check its signature line names the
  same key (name and key hash) as `keys/logs/audit.vkey`;
- copies published outside GitHub (on diagnos' website or in its applications, see
  [keys/README.md](keys/README.md)) must match these byte for byte;
- a copy you made earlier, from a clone you trust, is as good as any.

Then point the verifier at your own copy with `-keys DIR` (same layout as `keys/`).

## 3. Verify a witness record

A witness record (`data/v1/<log>/witness/YYYY/MM/DD/HHMMSSZ.json`) says: *at this time the witness
saw this log at this size with this root, signed by the log; it cosigned it; and here is the proof
that this tree extends the one in the previous record.*

```sh
go run ./tools/verify witness data/v1/audit/witness/2026/10/01/142005Z.json
```

```
data/v1/audit/witness/2026/10/01/142005Z.json
  ok   log signature  transparency.example/audit/v1 (key 12072373)
  ok   cosignature    witness.example/auditor/v1 at 2026-10-01T14:20:05Z
  ok   tree head      size 188948, root OLDajDFi/5PRy2eGhk/j6TKBonhqGIZh9HJOvkoxXAw=
  ok   consistency    188911 → 188948 (15 hashes) from data/v1/audit/witness/2026/10/01/141506Z.json

OK: 1 file, 4 checks
```

What each line checks:

- **log signature**: `checkpoint.note` carries a valid Ed25519 signature by the log's key over the
  checkpoint body. This is what makes the tree head the log's own statement, not the witness's.
- **cosignature**: the note also carries a valid `cosignature/v1` by the witness's key, and the time
  inside that cosignature is `witnessedAt` (and the file name).
- **tree head**: the `size` and `root` the record repeats are the ones the signed body states.
- **consistency**: the previous record (named in `previous.record`) holds exactly `previous.size`
  and `previous.root`, and `consistency` is a valid RFC 9162 §2.1.4 proof that the tree of
  `previous.size` leaves is a prefix of this one. The first record of a log has no previous record
  and nothing to prove; it is trusted on first use.

Checking the whole chain of a log, record by record, proves the log only ever grew from the first
record to the last. `verify all` does exactly that (section 7).

### The signatures by hand, with OpenSSL

The signatures are plain Ed25519, so OpenSSL can check them without the Go tool. A signed note is
the body (origin, size and root lines, each ending in a newline), a blank line, then signature lines
`— <key name> <base64(key hash[4] ‖ signature)>`.

```sh
R=data/v1/audit/witness/2026/10/01/142005Z.json
K=keys/logs/audit.vkey
NAME=$(cut -d+ -f1 $K)

# The signed body: every line before the blank line.
jq -r .checkpoint.note $R | awk '/^$/ { exit } { print }' > body

# The log's public key as DER (an Ed25519 SubjectPublicKeyInfo prefix, then the 32 key bytes).
{ printf '302a300506032b6570032100' | xxd -r -p; cut -d+ -f3- $K | base64 -d | tail -c 32; } > log.der

# The signature: the line by the log's key, minus its 4-byte key hash.
jq -r .checkpoint.note $R | grep "^— $NAME " | cut -d' ' -f3 | base64 -d | tail -c 64 > log.sig

openssl pkeyutl -verify -pubin -inkey log.der -keyform DER -rawin -in body -sigfile log.sig
```

The witness's `cosignature/v1` signs a slightly different message: `cosignature/v1\n`, then
`time <unix seconds>\n`, then the same body. The time travels inside the signature line, as eight
big-endian bytes after the key hash:

```sh
W=keys/witness/auditor.vkey
WNAME=$(cut -d+ -f1 $W)
jq -r .checkpoint.note $R | grep "^— $WNAME " | cut -d' ' -f3 | base64 -d > cosig.raw
T=$(head -c 12 cosig.raw | tail -c 8 | od -An -tu8 --endian=big | tr -d ' ')
date -u -d "@$T" +%FT%TZ          # must equal witnessedAt

{ printf '302a300506032b6570032100' | xxd -r -p; cut -d+ -f3- $W | base64 -d | tail -c 32; } > wit.der
tail -c 64 cosig.raw > cosig.sig
{ printf 'cosignature/v1\ntime %s\n' "$T"; cat body; } > cosig.msg
openssl pkeyutl -verify -pubin -inkey wit.der -keyform DER -rawin -in cosig.msg -sigfile cosig.sig
```

Both must print `Signature Verified Successfully`; change one byte of `body` and both fail.

## 4. Verify against the log itself

The consistency proof in a record was supplied by the log and checked by the witness. To check it
without trusting either, rebuild it from the log's own data:

```sh
# The log today extends what the witness saw then:
go run ./tools/verify consistency data/v1/audit/witness/2026/10/25/140503Z.json

# Two records, then up to the log's current checkpoint:
go run ./tools/verify consistency \
  data/v1/audit/witness/2026/10/01/000005Z.json data/v1/audit/witness/2026/10/25/140503Z.json
```

The verifier fetches the log's current `checkpoint` from the record's `url` (or `-log URL`),
verifies the log's signature on it, and reads the **hash tiles** it needs
(`tile/<L>/<N>[.p/<W>]`, [C2SP tlog-tiles](https://c2sp.org/tlog-tiles)), typically a handful of
small files. It never reads entry bundles: hashes are commitments, entries are the log's data. From
the tiles it builds the RFC 9162 consistency proofs between the witnessed sizes and today's size, and
verifies them against the signed roots.

Nothing in that path has to be trusted. A proof only verifies if the same node hashes reproduce both
signed roots, so a log (or anything between you and it) that serves a wrong hash fails the check.
What it proves: the tree the log serves today, under its own signature, contains the tree the
witness cosigned, unchanged. If the log is smaller than a witnessed size, the tool reports a
rollback.

The example logs (`transparency.example`) are not online; this step only works on real records.

## 5. Verify the hourly timestamps

Every hour the witness writes `data/v1/timestamps/YYYY/MM/DD/HHZ.json` and, next to it, the
authority's raw `HHZ.tsr`. The record's `subject` names, for each log, the latest witness record
(path and SHA-256 of its bytes) and, in `prev`, the previous hourly record (path and SHA-256 of its
bytes). The `imprint` is SHA-256 of the subject in RFC 8785 canonical JSON, and that is what the
authority signed with the time.

```sh
go run ./tools/verify timestamp -openssl data/v1/timestamps/2026/10/01/14Z.json
```

```
data/v1/timestamps/2026/10/01/14Z.json
  ok   imprint        53b5c07e4257f4de182267dbc3ce0cee8f73a57a00bb30db95b5dc5c827f246c = SHA-256(JCS(subject))
  ok   subject audit  size 188794, data/v1/audit/witness/2026/10/01/140005Z.json
  ok   subject signs  size 9236, data/v1/signs/witness/2026/10/01/132005Z.json
  ok   chain          previous data/v1/timestamps/2026/10/01/13Z.json, sha256 bd53c49857d6dc1b75bceddd839fc7b7a0663231b04c329a27245bd328ca741c
  ok   token          example-tsa, genTime 2026-10-01T14:00:08Z, serial 101a
  ok   openssl        TSA signature and chain verify against keys/tsa/example-tsa.pem

OK: 1 file, 6 checks
```

### By hand, with jq, sha256sum and OpenSSL

```sh
F=data/v1/timestamps/2026/10/01/14Z

# 1. The imprint is the hash of the canonical subject. The subject holds only ASCII strings,
#    integers, objects and null, so jq's sorted compact output is exactly RFC 8785.
jq -jcS .subject $F.json | sha256sum
jq -r .imprint $F.json                     # the same 64 hex digits

# 2. The authority signed that imprint, with a certificate that chains to its CA.
openssl ts -verify -digest "$(jq -r .imprint $F.json)" -in $F.tsr \
  -CAfile keys/tsa/$(jq -r .token.provider $F.json).pem
# Verification: OK

# 3. What the authority attests (genTime is the time), and that it matches the record.
openssl ts -reply -in $F.tsr -text | grep -E 'Status:|Time stamp:|Message data' -A2
jq .token $F.json

# 4. The link: the previous hour's file hashes to what this subject says.
sha256sum "$(jq -r .subject.prev.record $F.json)"
jq -r .subject.prev.sha256 $F.json         # the same 64 hex digits

# 5. Each witness record the subject names hashes to what it says.
jq -r '.subject.logs[] | "\(.sha256)  \(.record)"' $F.json | sha256sum -c
```

`openssl ts -verify` checks the token's CMS signature, that the signing certificate has the
time-stamping extended key usage, that it chains to the CA in the PEM file, and that the token's
imprint is the digest you gave it. TSA certificates expire after some years; to check an old token,
verify it as of its own time with `-attime "$(date -u -d "$(jq -r .token.genTime $F.json)" +%s)"`.
(`go run ./tools/verify timestamp -openssl` always does this.)

### What the chain proves

Each hourly subject contains the SHA-256 of the previous hourly record, whose subject contains the
SHA-256 of the one before, and so on. Every hour an independent authority signed the newest link
with the time. So:

- the tree heads named in an hour existed by that hour's `genTime`, according to the authority;
- no past hour can be deleted, edited or reordered without breaking every later link, and the later
  tokens cannot be re-made without the authorities;
- the witness cannot backdate a record: anything it adds later would not be covered by the tokens
  already issued.

The witness tries several free authorities in order (FreeTSA, DigiCert, Sectigo, GlobalSign, Certum,
Apple) and moves to the next on any error; `attempts` lists the ones that failed. If all fail, the
hour is still recorded with `"token": null`, so the gap is visible and the chain is not broken; the
page and `verify` show it as a warning.

## 6. Verify a finding

A finding (`data/v1/<log>/findings/...json`) is the witness's claim that the log misbehaved. It is
only worth anything if it is evidence, so check it as such:

```sh
go run ./tools/verify finding data/v1/signs/findings/2026/10/01/133507Z.json
```

The tool checks that `observed.note` is signed by the **log's** key, that `witnessed.note` is signed
by the log and cosigned by the witness, and that the two conflict as `kind` says:

| kind | the evidence |
| --- | --- |
| `equivocation` | two log-signed checkpoints of the same size with different roots. The log showed two histories. |
| `rollback` | a log-signed checkpoint smaller than one the witness already cosigned. |
| `inconsistent` | a larger log-signed checkpoint, and the log's consistency proof (`consistency`) does not verify. |

You can redo the signature checks by hand exactly as in section 3. After a finding the witness
stops cosigning that log. A finding is a security event; [SECURITY.md](SECURITY.md) says how it is
handled.

## 7. Verify everything at once

```sh
go run ./tools/verify all -openssl
```

From a local clone, `all` reads every file under `data/v1` and checks:

- every file is one the layout allows (no stray files, no orphan tokens);
- every witness record, as in section 3, and that each one's `previous` is exactly the record before
  it in the same log: no gaps, no forks, nothing removed;
- every hourly record, as in section 5, that each links to the hour before it, and that each hour's
  subject names the newest record witnessed before that hour;
- every finding, as in section 6;
- that `state.json`, `latest.json` and every month index say exactly what the records say. The page
  reads these summaries; this check is what keeps them honest;
- the run records and every view built from them, as in section 10, and the archived releases, as
  in section 11. `verify all` takes two more flags: `-complete`, which demands an unbroken run
  chain from the first run to the latest, and `-cosign`, which re-checks every archived release
  with cosign.

```sh
go run ./tools/verify all -openssl -complete -cosign
```

CI runs that command every Monday. Every hour it also runs the per-record checks on the files the
auditor committed since its last successful run, rejects any commit that modifies or deletes an
existing record that is not a view, and validates every new file against
[`schemas/v1`](schemas/v1). It does not run per commit: the auditor commits every five minutes.

## 8. When something does not verify

The exit status is 0 when every check passed, 1 when any failed, 2 for bad usage. Warnings (an hour
without a token, a second-witness signature that cannot be checked because its key is not published
yet, a witness that reports the published history changed) do not fail the run. A gap in the run chain fails only with `-complete`
(section 10).

If a real record does not verify, that is what this repository exists to expose. Keep a copy of the
files exactly as you got them (they are evidence), and report it: privately if you think it reveals
a vulnerability in the logs, the witness or the verifier ([SECURITY.md](SECURITY.md)), otherwise in
an issue. Please include the command, its full output, the commit you checked out
(`git rev-parse HEAD`) and where your keys came from.

## 9. Reference: the formats

| Thing | Format | Spec |
| --- | --- | --- |
| checkpoint body | `<origin>\n<size>\n<base64 root>\n` (plus optional extension lines) | [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint) |
| signed note | body, blank line, lines `— <name> <base64(keyhash[4] ‖ sig)>` | [C2SP signed-note](https://c2sp.org/signed-note) |
| log signature | Ed25519 over the body; key hash over `name ‖ "\n" ‖ 0x01 ‖ key` | signed-note |
| witness cosignature | signature bytes `keyhash[4] ‖ time[8, big-endian] ‖ Ed25519[64]` over `cosignature/v1\ntime <t>\n<body>`; key hash over `name ‖ "\n" ‖ 0x04 ‖ key` | [C2SP tlog-cosignature](https://c2sp.org/tlog-cosignature) |
| Merkle hashes | leaf `SHA-256(0x00 ‖ leaf)`, node `SHA-256(0x01 ‖ left ‖ right)` | RFC 9162 §2.1.1 |
| consistency proof | RFC 9162 §2.1.4, nodes in base64 | RFC 9162 §2.1.4.2 |
| tiles | `tile/<L>/<N>[.p/<W>]`, 256 hashes per full tile, N in groups of three digits (`x001/x234/067`) | [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) |
| hourly imprint | SHA-256 of the RFC 8785 (JCS) form of `subject` | RFC 8785 |
| timestamp token | the `TimeStampResp` (status and token) in DER, as the authority returned it | RFC 3161 |
| run record | `cia-run/v1`: levels, checks and codes per service; `prev` is the SHA-256 of the previous record's bytes | [`cia-run.schema.json`](schemas/v1/cia-run.schema.json) |
| run record, two witnesses | `cia-run/v2`: each witness's signed measurement (`witnesses`) and the combined verdicts (`services`); same path and chain as v1 | [`cia-run-v2.schema.json`](schemas/v1/cia-run-v2.schema.json) |
| measurement note | a signed note, `diagnos-witness/measurement/v1`, `witness <id>`, `slot <slot>`, `request <SHA-256 or none>`, `measured <SHA-256 of the RFC 8785 form of measured>`; Ed25519 (`0x01`) with the witness's key | [C2SP signed-note](https://c2sp.org/signed-note), RFC 8785 |
| incident event, incident list, change events | `cia-incident-event/v1` (one change of an automatic incident), `cia-incident-list/v1` (declared and automatic incidents in one list), `cia-changes/v1` (the last 500 change events) | [`cia-incident-event`](schemas/v1/cia-incident-event.schema.json), [`cia-incident-list`](schemas/v1/cia-incident-list.schema.json), [`cia-changes`](schemas/v1/cia-changes.schema.json) |
| day file | `cia-day/v1`: three strings of 288 letters (`o` `w` `f` `-`) per service, one per five-minute slot, and the spans that are not green | [`cia-day.schema.json`](schemas/v1/cia-day.schema.json) |
| release manifest | `release-manifest/v1`: every file of a release with SHA-256, size and served path; its SHA-256 is the release digest | [`release-manifest.schema.json`](schemas/v1/release-manifest.schema.json) |
| release signature, provenance | [Sigstore bundles](https://docs.sigstore.dev/about/bundle/): a message signature over `manifest.json`, and a DSSE in-toto statement with SLSA provenance v1 for the same digest | cosign |
| declared incident | Markdown with a strict front matter (`categories` C, I, A; optional `relates`) and a bilingual body | [`incidents/README.md`](incidents/README.md) |
| data files | JSON Schema 2020-12 | [`schemas/v1`](schemas/v1) |

The leaves themselves are commitments, `SHA-256("diagnos.audit.v1\0" ‖ salt ‖ JCS(record))` (and
`diagnos.signs.v1` for signatures), with a random 32-byte salt per item kept privately alongside the
item. Whoever holds an item and its salt can prove its inclusion in the log; nobody can learn an item
from the log.

## 10. Verify the run records and the views

Every five minutes the auditor writes one **run record**,
`data/v1/cia/runs/YYYY/MM/DD/HHMMZ.json`, named after its five-minute slot (the run's start time
rounded down to a multiple of five minutes). For each of the four services it holds, for each
dimension, a `level` (`ok`, `warn`, `fail`, or `none` for *not measured*) and the `checks` it is
the worst of. Each check has an `id` and a `code`, and the code fixes the level:

| Check | ok | warn | fail | none |
| --- | --- | --- | --- | --- |
| `healthz` (availability) | ok, retried | slow, tls-expiring | timeout, connect-error, tls-error, http-status, content-type, invalid-body, wrong-service, wrong-environment | vantage |
| `checkpoint:<log>` (availability) | ok | | unreachable | vantage |
| `release` (integrity) | verified | pending, unverified, unsigned, unmonitored | digest-mismatch, claim-mismatch, signature-invalid, provenance-invalid, served-mismatch | unreachable, vantage |
| `log:<log>` (integrity) | ok | log-error | finding, halted | unreachable, vantage |
| `incidents` (confidentiality) | clear | incident-low, invalid | incident-high | unavailable |

The dimension's level is the worst of its checks (`fail` over `warn` over `ok` over `none`). A run
record's `prev` names the previous run record and the SHA-256 of its exact bytes, so the records
form a chain like the hourly ones: a record cannot be removed or edited without breaking every
later link.

Probes also record how long they took: each `healthz` check has `timings` (DNS, connect, TLS, first
byte and total, in milliseconds; the first byte is counted from the start of the attempt, so it
includes the three phases before it) and each run has the `vantage` it ran from
(`scaleway:fr-par`). The rest of this section is about `cia-run/v1`; `cia-run/v2`, which the
records have from the day the second witness joined, keeps these rules for the combined verdicts and
adds the ones of section 13.
Day files add, per service, `latency {p50Ms, p95Ms, samples, slotsMs}`: the nearest-rank percentiles
of the `healthz` latency of that day and the latency of each of its 288 slots, and the summary has
`p95Ms` per day. These fields are additive and
optional: records written before them do not have them.

**Late data is never an outage.** A slot with no run record is `-` (not measured) in the day files,
never `f`. Each run may carry `control`: a probe of a host outside diagnos, with `ok` true or false.
When the control probe failed and the `healthz` probe of every service failed at the transport
level (`timeout`, `connect-error`, `tls-error`), the auditor's own network failed, not the
services: the run is a *vantage failure*. Every network check of every service (`healthz`,
`checkpoint`, `release`, `log`) is then recorded with level `none` and code `vantage`, the run opens
no incident and counts in no uptime. `verify cia` enforces it both ways: a run with any `vantage`
check must have all four kinds of check of every service at `none`/`vantage`, and `control`
present with `ok` false; and a run with `control.ok` false in which every service's `healthz` is a
transport `fail` is an error, because it had to be recorded as a vantage failure.

**Incidents are facts too.** Declared incidents arrive in the snapshots
(`data/v1/cia/incidents/YYYY/MM/DD/HHMMZ.json`, section 12). The auditor opens, updates and resolves
*automatic* incidents itself, each change as an immutable event,
`data/v1/cia/incidents/events/YYYY/MM/DD/<id>-<seq>.json`: an availability incident after 3
consecutive failed slots, an integrity incident for an invalid release, differing served files or
a witness finding. `verify cia` checks that the events of an id are numbered 1, 2, 3 without gaps
(`opened`, then `updated`, with `resolved` only last), that `categories`, `services` and
`startedAt` never change, that they agree with the id and with the run records, that `relates` of
a declared incident names an automatic incident that was opened, and the **coverage**: every
maximal run of at least 3 consecutive recorded failing slots of a service's availability, and every
failing integrity slot, lies inside an incident of that service. A failure the auditor did not turn
into an incident is therefore detectable. `data/v1/cia/incidents.json` lists both kinds: the
declared items (`source: "declared"`) and one item per automatic incident built from its latest
event (`source: "auditor"`), newest `startedAt` first, ties by id; it is recomputed and compared
byte for byte.

**How an incident colours the record.** `low` and `medium` are `warn`, `high` and `critical` are
`fail`; category `C` colours confidentiality, `I` integrity, `A` availability. A published incident
affects dimension *d* of service *s* in a slot when *s* is among its services, the category of *d*
is among its categories, it started before the slot ended and it was not resolved before the slot
began; the worst affecting level counts. In the day files, availability and integrity show the
worse of the run record's level and the incident level; confidentiality shows the incident level
alone (the record's own level only while no declared snapshot exists yet). Slots without a run stay
`-`: incidents never colour what was not measured. The colours are therefore a function of the
*latest* state of the incidents, while each run record keeps what was known when it ran. The
summary is derived from the day files, so a declared major availability incident lowers uptime.

**Change events.** `data/v1/cia/changes.json` holds the last 500 change events, newest first,
derived only from run records and incident facts; `verify cia` derives them again and compares
byte for byte. `data/v1/cia/changes-recent.json` is its first 30 events, small enough for a first
screen, and is checked the same way. The rules are fixed. The first recorded slot sets each service's state without an
event. A level change is entered after the debounce: for availability 3 consecutive recorded slots
at the new level when it is worse and 2 when it is better, for integrity 1; slots not measured
(including vantage failures) are skipped, neither counted nor interrupting. Confidentiality has no
level events: its changes are incident events. The other kinds are a newly verified release, a
witness finding, an incident opened, updated, resolved or removed, *record delayed* (15 minutes or
more without a record, never "down"), *record resumed* and the auditor's *vantage* failure. The
feeds carry the same events, 100 of each, and are a convenience for subscribers: the record is
the files under `data/`.

```sh
go run ./tools/verify cia
```

For every run record it checks what JSON Schema cannot say: each code has the level the table gives,
each dimension is the worst of its checks, the checks come in the table's order, the slot is the
file name, `prev` is the SHA-256 of the previous record's bytes, and there is at most one record per
slot. Then it **recomputes every view from the records** and compares what they say (a view written
on one line and an indented one are the same view): the day files
(`data/v1/cia/days/`, apart from their `updatedAt`), `summary.json`, `latest.json`,
`incidents.json`, `changes.json` and `changes-recent.json`. A view that says anything the records do
not is an error.

Without `-complete` the check accepts a slice of the history: the oldest record present may link to
a predecessor that is not in the checkout, `firstRun` may be older than the oldest record present,
and a day slot without a record file is skipped. That is what a shallow clone, or the example data,
looks like. With `-complete` none of that is allowed: the chain must run unbroken from the first
run to the latest. CI runs it with `-complete` every week; on the examples it fails on purpose,
because they are a slice.

```sh
go run ./tools/verify cia -complete                     # the whole history, no gaps
go run ./tools/verify cia data/v1/cia/runs/2026/10/27/1405Z.json   # just these records
go run ./tools/verify cia -root examples                # the example data
```

### By hand

```sh
R=data/v1/cia/runs/2026/10/27/1405Z.json
jq -r .prev.record $R                        # the previous run record
sha256sum "$(jq -r .prev.record $R)"         # the same 64 hex digits as ...
jq -r .prev.sha256 $R                        # ... this

# What one service reported in this slot:
jq '.services.vault | {availability: .availability.level, integrity: .integrity.level}' $R
```

A day file has, per service and dimension, a string of 288 letters (`o` ok, `w` warn, `f` fail, `-`
not measured), one per slot; slot *i* of a day is `(hour × 60 + minute) / 5`, so 14:05Z is slot 169,
the 170th letter:

```sh
jq -r .services.vault.availability data/v1/cia/days/2026/10/27.json | cut -c170
```

The 90-day view colours a whole day from its slot counts (ok, warn, fail), for every service:

| Dimension | Day letter |
| --- | --- |
| availability | `-` if nothing was measured; `f` if at least three slots failed (15 minutes); `w` if one or two failed or any was degraded; else `o` |
| integrity, confidentiality | `-` if nothing was measured; `f` if any slot failed; `w` if any was `warn`; else `o` |

and its uptime is `(ok + warn) / (ok + warn + fail)` of the availability slots in the window.

### Dated by the hour

The hourly record's subject gains `cia`: the path and SHA-256 of the newest run record when the hour
was stamped. `verify timestamp` checks that the file exists and hashes to that value; because run
records are chained, the one token per hour that dates the witness also dates the whole CIA history.

```sh
sha256sum "$(jq -r .subject.cia.record data/v1/timestamps/2026/10/27/14Z.json)"
jq -r .subject.cia.sha256 data/v1/timestamps/2026/10/27/14Z.json   # the same 64 hex digits
```

## 11. Verify a release with cosign

Every service serves, from the same place, the evidence for the release it runs:

```
/.well-known/diagnos/manifest.json             every file of the release: SHA-256, size, where it is served
/.well-known/diagnos/manifest.json.sig         Sigstore bundle: signature over manifest.json
/.well-known/diagnos/provenance.sigstore.json  Sigstore bundle: SLSA provenance for the same digest
/healthz                                       names the digest of the manifest it runs
```

The **release digest** is the SHA-256 of the exact bytes of `manifest.json`. The auditor verifies
each new digest once and archives the evidence under
`data/v1/cia/releases/<service>/<digest>/` with its `verdict.json`, so it outlives the deployment.
A brand-new release shows `pending` (yellow) for at most one five-minute cycle, until the integrity
check has judged it. `keys/signers.json` pins, per service, the only identity that counts: a GitHub
Actions workflow on one branch of one repository. For `frontend`, `vault`, `sign` and `status` it is
diagnos' monorepo, `.github/workflows/pipeline.yml` on `main`.

```sh
go run ./tools/verify release data/v1/cia/releases/vault/<digest>          # structure
go run ./tools/verify release -cosign data/v1/cia/releases/vault/<digest>  # and the signatures
```

Without `-cosign` it checks that the SHA-256 of `manifest.json` is the directory name, that the
manifest is valid and says the same as `verdict.json`. With `-cosign` it also runs the two cosign
commands below, with the identity read from `keys/signers.json`.

### By hand

```sh
SVC=vault
D=data/v1/cia/releases/$SVC/<digest>
S=keys/signers.json
ISSUER=$(jq -r ".services.$SVC.issuer" $S)
REPO=$(jq -r ".services.$SVC.repository" $S)
REF=$(jq -r ".services.$SVC.ref" $S)
IDENTITY="$REPO/$(jq -r ".services.$SVC.workflow" $S)@$REF"

sha256sum $D/manifest.json        # must be <digest>, the directory name

cosign verify-blob --bundle $D/manifest.json.sig \
  --certificate-oidc-issuer "$ISSUER" --certificate-identity "$IDENTITY" \
  --certificate-github-workflow-repository "${REPO#https://github.com/}" \
  --certificate-github-workflow-ref "$REF" \
  --certificate-github-workflow-sha "$(jq -r .commit $D/manifest.json)" \
  $D/manifest.json

cosign verify-blob-attestation --bundle $D/provenance.sigstore.json --type slsaprovenance1 \
  --certificate-oidc-issuer "$ISSUER" --certificate-identity "$IDENTITY" \
  $D/manifest.json
```

The first command proves the manifest was signed with a short-lived certificate that Sigstore's
Fulcio issued to that workflow identity, and that the signature is in the public Rekor log. The
second proves the SLSA provenance names the same digest and was signed by the same identity.
cosign cannot require the repository's and owner's numeric ids, which `signers.json` also records
(they survive renames and cannot be re-registered by someone else); they are in the certificate's
Fulcio extensions `1.3.6.1.4.1.57264.1.15` (repository) and `1.3.6.1.4.1.57264.1.17` (owner), and
the auditor requires them to match.

### The served bytes

For static content the manifest also says where each file is served. Compare one with the live
site:

```sh
jq -r '.files[] | select(.served != null) | "\(.sha256)  \(.served)"' $D/manifest.json | head -3
curl -s https://vault.diagnos.health/favicon.svg | sha256sum   # a path from the list above
```

The auditor samples these files continuously (25 per five-minute cycle by default, in manifest
order), so a full pass takes from tens of minutes for a small site to many hours for a large one. A
Worker's script (`served: null`) cannot be compared: see *What it proves, and what it does not* in
the [README](README.md).

### The status page

`status` is a service like the others, and static. `https://status.diagnos.health/healthz` has
`build.digest`, which is the SHA-256 of `https://status.diagnos.health/.well-known/diagnos/manifest.json`;
the bundles are next to it. The same files are served on its second door,
`https://imgexam-auditor-production.s3-website.fr-par.scw.cloud/`, and the auditor samples both.
The auditor publishes a new version of the page only after it has verified the release as above, so
what `verify release` says about the archived `status` release is what both doors serve.

## 12. Verify the declared incidents

Some things cannot be measured from outside, so diagnos **declares** them in
[`incidents/`](incidents) (the format, the categories `C`, `I`, `A` and what each field does are in
[`incidents/README.md`](incidents/README.md)). The auditor opens incidents of its own too; those are
the events of section 10.

```sh
go run ./tools/verify incidents incidents/*.md examples/incidents/*.md
```

It parses each file with the same grammar the auditor uses, applies every rule (file name and `id`,
no `auto-` slug, fields and `categories`, times, severity and status, `resolved_at` only when
resolved, lengths, the bilingual body) and prints which files are published. A file with
`publish: false` is checked and then ignored, which is why the shipped template is valid but never
counted.

The auditor writes a snapshot of the declared incidents,
`data/v1/cia/incidents/YYYY/MM/DD/HHMMZ.json`, whenever they change. `data/v1/cia/incidents.json`
repeats its items next to the automatic incidents and says which snapshot it used (`declared`).
Each declared item records the Git `blob` of its file and the commit the folder was read at, so you
can check that what is shown is what was committed (this needs the full history, `git fetch
--unshallow`):

```sh
C=$(jq -r .declared.commit data/v1/cia/incidents.json)
jq -r '.incidents[] | select(.source == "declared") | "\(.blob) \(.file)"' data/v1/cia/incidents.json
git show "$C:incidents/<id>.md" | git hash-object --stdin     # the same blob id
```

Run records link to the snapshot in force (`incidents.snapshot.sha256`) and the hourly timestamps
pin the run records, so editing or deleting a declaration later leaves a visible trail. What
`verify cia` adds is the colours: it recomputes each day's letters from the latest state of the
incidents and the rule in section 10, checks that every `relates` names an automatic incident, and
that no lasting failure went without an incident. It cannot tell whether an incident that was
never declared happened.

## 13. Verify the two witnesses

The services are measured from two regions, Europe and Latin America, each by its own **witness**
(`europe`, `latam`) with its own key. From the day the second witness joined, the run records are
`cia-run/v2`. They live at the same paths and in the same chain as `cia-run/v1` (`prev` links the
previous record whatever its version), but they have another id because their meaning is not the
same: the availability of a service is now a verdict over what two witnesses measured, and a reader
that took it for one witness's answer would misread it.

A `cia-run/v2` record has two parts:

- `witnesses.<id>`: `status` (`ok` or `unavailable`), the `reason` when a witness is missing
  (`timeout`, `unreachable`, `rejected`, `signature`, `invalid`, `skew`, or `off` when it is not
  configured), and, when it measured, its signed `note` and the `measured` object it signs: every
  service's probe (code, error class, attempts, status, TLS version and expiry, address, CDN
  location, bytes and the phases of the time), what it did with each transparency log, and its
  control probe. The primary witness (Europe) always has an entry, because it writes the record.
- `services`: the **combined** result of each service, in the shape of v1, which anyone can
  recompute from the measurements:

| Europe | Latin America | Combined |
| --- | --- | --- |
| did not measure | did not measure | `none`, `vantage` |
| measured | did not measure (silent, unavailable, `vantage` or `challenged`) | what Europe measured: one witness's own retry is the confirmation |
| did not measure | measured | what Latin America measured |
| failed | failed | `fail`, Europe's code: down, because the two agree |
| failed | up or slow | `warn`, `regional`: reachable from one region only |
| up or slow | failed | `warn`, `regional` |
| otherwise | | the worse of the two, with the code of the first (Europe, then Latin America) at that level |

The same rule combines the `checkpoint:<log>` checks. The `log:<log>` checks are evidence, not a
vote: the worst of the witnesses counts, so a finding or a halt seen from one region fails
integrity. A release is judged from Europe's probe alone. A witness that did not measure is *not
measured*, never an outage.

```sh
go run ./tools/verify cia           # or: verify all
```

For a `cia-run/v2` record it checks, on top of section 10: that Europe has an entry and that every
entry is consistent with its status; **the signature of each measurement note** with the key of its
witness (`keys/witness/auditor.vkey`, `keys/witness/latam.vkey`), and that the note's lines agree
with the record: the witness, the slot of the run (a note cannot be moved to another run), `request`
(`none` for Europe, a digest for a witness that answers a request) and `measured`, the SHA-256 of the
canonical (RFC 8785) JSON of the `measured` object, so a number changed after it was signed does not
verify; that each witness measured exactly the services and the logs of the run, and that each probe
and log is consistent with its own code (a failed probe names the phase it failed in, a timeout has
no status, the phases fit in the total); the vantage rule for each witness on its own (a witness
whose control probe failed, and whose every probe failed at the transport level, must be recorded as
not measured, never as an outage); that the combined checks are exactly what the measurements
combine to, by the table above; that two witnesses which read different roots for one size of a log
(a *split view*) are recorded as a failing evidence check that names a finding; and the files the
measurements name (each witness record and finding is in the namespace of the witness that made it,
exists, and agrees with the size and root reported). A secondary witness's `peer` is its check of the
primary's latest record: `ok` says it saw the bytes the repository has, and the verifier compares;
`mismatch` is its signed statement that the published history changed, which the report shows as a
warning and the change stream as a `witness-disagreement` event.

The second witness keeps its own chain of witness records and findings under
`data/v1/witnesses/latam/<log>/`, cosigned with its own key and linked to its own previous record;
`verify witness` and `verify finding` check them like the primary's, and `verify all` walks both
chains. The primary witness's files stay where they have always been.

### By hand

The digest of a measurement is that of the canonical JSON of `measured`. For these records, whose
strings are plain ASCII and whose numbers are integers, `jq` produces it:

```sh
R=data/v1/cia/runs/2026/10/01/1405Z.json
jq -jcS '.witnesses.latam.measured' $R | sha256sum        # the same 64 hex digits as ...
jq -r '.witnesses.latam.note' $R | grep '^measured '       # ... this line of the signed note
```

The signature is plain Ed25519 over the five lines of the note, so OpenSSL checks it the way section 3
checks a checkpoint, with the witness's key (the same 32 bytes as in its `cosignature/v1` key):

```sh
W=keys/witness/latam.vkey
NAME=$(cut -d+ -f1 $W)
jq -r .witnesses.latam.note $R | awk '/^$/ { exit } { print }' > note.txt
{ printf '302a300506032b6570032100' | xxd -r -p; cut -d+ -f3- $W | base64 -d | tail -c 32; } > w.der
jq -r .witnesses.latam.note $R | grep "^— $NAME " | cut -d' ' -f3 | base64 -d | tail -c 64 > w.sig
openssl pkeyutl -verify -pubin -inkey w.der -keyform DER -rawin -in note.txt -sigfile w.sig
```

### What the views add

A day file keeps, per service and witness, `regions.<id>`: one letter per slot from that witness's
probe, the latency of the probes that succeeded (`slotsMs`, 288 values) with their statistics, the
phases, the failures counted by class, the retries and the uptime. The statistics are *nearest rank*:
the value at position `ceil(p × n / 100)` of the `n` sorted values, with `minMs` as p0 and `maxMs`
as p100, and the mean rounded half up in integers. Only probes that succeeded are latency samples:
a timeout is an error, counted in `errors`, not a very slow answer. With fewer than 20 samples p95
is the maximum, and with fewer than 100 so is p99. `latest.json` adds each witness's probe per
service and a `witnesses` object, and `summary.json` the 90 days of each region. `verify cia`
recomputes all of them. The change stream adds `witness-unavailable` (a witness absent for three
runs in a row), `witness-restored` (two runs back) and `witness-disagreement` (an answer that did not
verify, a peer `mismatch`, or a split view); their summaries speak of the record, never of the
services.

```sh
jq -r '.services.vault.regions.latam.availability' data/v1/cia/days/2026/10/01.json | cut -c169-173
jq '.services.vault.regions.europe.latency | {samples, p50Ms, p95Ms, p99Ms, maxMs}' data/v1/cia/days/2026/10/01.json
```
