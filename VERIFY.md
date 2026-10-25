# Verifying the witness record

This is how to check, with your own tools, everything the record and the page claim. Nothing here
asks you to trust diagnos, the witness, this repository's web page or its CI. Each step says what it
proves and what it does not.

**Try every command on the example data first:** run them from `examples/` (or add `-root examples`
to the `go run` commands). The examples are signed with published example keys and include an
hour when one authority failed, an hour when every authority failed, and one finding, so you can see
every outcome. Paths below are examples too;
use the ones of the record you are checking (the page's *How to verify* panel fills them in).

1. [Get the record](#1-get-the-record)
2. [Decide which keys to trust](#2-decide-which-keys-to-trust)
3. [Verify a witness record](#3-verify-a-witness-record)
4. [Verify against the log itself](#4-verify-against-the-log-itself)
5. [Verify the hourly timestamps](#5-verify-the-hourly-timestamps)
6. [Verify a finding](#6-verify-a-finding)
7. [Verify everything at once](#7-verify-everything-at-once)
8. [When something does not verify](#8-when-something-does-not-verify)
9. [Reference: the formats](#9-reference-the-formats)

## What you need

| Tool | For | Notes |
| --- | --- | --- |
| Go 1.24 or later | `tools/verify` | Its only dependency is `golang.org/x/mod`, fetched through the Go checksum database. |
| OpenSSL 1.1.1 or later | RFC 3161 tokens, and Ed25519 by hand | `openssl version` |
| `jq`, `sha256sum`, `base64`, `xxd`, `awk` | recomputing hashes by hand | coreutils / standard packages |

## 1. Get the record

```sh
git clone --depth 1 https://github.com/diagnos-tech/audit
cd audit
```

A shallow clone is enough for any single record and its neighbours. `verify all` reads every file,
so it needs a full checkout of `data/` (still a shallow history).

Without cloning, every `go run` command below except `all` accepts the published site as its root:

```sh
go run github.com/diagnos-tech/audit/tools/verify@latest witness \
  -root https://diagnos-tech.github.io/audit/ data/v1/audit/witness/2026/10/25/140503Z.json
```

Records never change once committed, so a copy you keep stays checkable forever, and keeping one is
itself a check: if a later copy of the repository disagrees with yours, the history was rewritten.

## 2. Decide which keys to trust

Every check depends on three kinds of public key, all in [`keys/`](keys):

| File | Key | Format |
| --- | --- | --- |
| `keys/logs/audit.vkey`, `keys/logs/signs.vkey` | each log's checkpoint key | signed-note verifier key, Ed25519 (`0x01`) |
| `keys/witness/auditor.vkey` | the witness's cosignature key | `cosignature/v1` verifier key (`0x04`) |
| `keys/tsa/<provider>.pem` | the CA chain of each time-stamping authority | PEM certificates; see [keys/tsa/README.md](keys/tsa/README.md) |

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
  reads these summaries; this check is what keeps them honest.

CI runs the same command every week, and on every push runs the per-record checks on the files the
push added, rejects any change to an existing dated record, and validates every new file against
[`schemas/v1`](schemas/v1).

## 8. When something does not verify

The exit status is 0 when every check passed, 1 when any failed, 2 for bad usage. Warnings (an hour
without a token) do not fail the run.

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
| data files | JSON Schema 2020-12 | [`schemas/v1`](schemas/v1) |

The leaves themselves are commitments, `SHA-256("diagnos.audit.v1\0" ‖ salt ‖ JCS(record))` (and
`diagnos.signs.v1` for signatures), with a random 32-byte salt per item kept privately alongside the
item. Whoever holds an item and its salt can prove its inclusion in the log; nobody can learn an item
from the log.
