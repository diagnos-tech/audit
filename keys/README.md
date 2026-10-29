# Public keys

The keys needed to check every record. They are public by nature; publishing them is the point.

| File | Key | Algorithm |
| --- | --- | --- |
| `logs/audit.vkey` | the `audit` log's checkpoint key, `transparency.diagnos.health/audit/v1` | signed-note Ed25519 (`0x01`) |
| `logs/signs.vkey` | the `signs` log's checkpoint key, `transparency.diagnos.health/signs/v1` | signed-note Ed25519 (`0x01`) |
| `witness/auditor.vkey` | the primary witness's key (Europe, the only one that publishes), `witness.diagnos.health/auditor/v1`; after a rotation, also the keys it replaced, see [Rotating a witness key](#rotating-a-witness-key) | `cosignature/v1` Ed25519 (`0x04`) |
| `witness/latam.vkey` | the second witness's key (Latin America), `witness.diagnos.health/latam/v1`; added later, see below; after a rotation, also the keys it replaced | `cosignature/v1` Ed25519 (`0x04`) |
| `tsa/<provider>.pem` | each time-stamping authority's CA chain | X.509, see [tsa/README.md](tsa/README.md) |
| `signers.json` | for each audited service, the CI identity whose signature a release must carry | JSON, `signers/v1` ([schema](../schemas/v1/signers.schema.json)) |

Each `.vkey` file is one line, `<name>+<key hash>+<base64(algorithm ‖ public key)>`, followed by a
newline; a witness's file can hold more than one, one per line, once the witness has rotated its key
(see [Rotating a witness key](#rotating-a-witness-key)). [VERIFY.md](../VERIFY.md#2-decide-which-keys-to-trust) shows how to recompute the key hash
and how to compare these keys with copies obtained elsewhere.

**The log and witness keys are added when the witness goes live, by a person, in a reviewed pull
request.** Until then `logs/` and `witness/` do not exist and the tools say so instead of guessing.
The authorities' roots in `tsa/` are already here: they are public, chosen by the witness's code,
and listed with their fingerprints in [tsa/README.md](tsa/README.md). The example keys used by the
example data live in [`examples/keys`](../examples/keys) and must never be copied here.

**The second witness's key is added after the first one's, in a pull request of its own.** The
services are measured from two regions by two independent witnesses, each with its own key, and
every run record from the second witness's first day on carries both of their signed measurements.
Until `witness/latam.vkey` exists the verifier treats the key as absent, which is not a failure: it
checks everything else about that witness's records, and says, with a warning, that their signatures
were not checked. A `latam.vkey` that exists and does not match the signatures is a failure, and the
primary witness's key is never optional. One file serves both kinds of signature the witness makes:
a `cosignature/v1` on a checkpoint, and an ordinary signed-note signature (algorithm `0x01`) on its
measurement; the second is derived from the same 32 bytes.

## `signers.json`: who may sign a release

The integrity of a service means: the release it runs was signed through Sigstore by a particular
GitHub Actions workflow. `signers.json` says which, for each service (`frontend`, `vault`, `sign`
and `status`):

| Field | Meaning |
| --- | --- |
| `issuer` | the OIDC issuer of the certificate: always `https://token.actions.githubusercontent.com` |
| `repository`, `workflow`, `ref` | the repository, the workflow file and the branch the workflow ran on; together `<repository>/<workflow>@<ref>` is the identity in the signing certificate |
| `repositoryId`, `ownerId` | the repository's and its owner's numeric GitHub ids, which survive renames and cannot be re-registered by someone else |

The monorepo's `.github/workflows/pipeline.yml` on `main` signs all four: `frontend`, `vault`,
`sign` and `status` (the status page: static, built by the same pipeline). The auditor is configured
with identical values (`monorepo_signer` in the monorepo's Terraform), and
[VERIFY.md](../VERIFY.md#11-verify-a-release-with-cosign) turns each entry into `cosign` flags.

Like the other keys, this file proves only that the repository agrees with itself. Compare it with
the auditor's configuration, and with the certificate inside a release's `manifest.json.sig`, which
names the workflow that signed it. Change it only in a reviewed pull request, together with the
workflow or the auditor setting it follows; a change here changes what a valid signature is. The
numeric ids come from `gh api repos/<owner>/<repo> --jq '.id, .owner.id'`.

## Rotation

A key is never edited in place. A new log key comes with a new origin (`…/v2`) and gets its own file;
old keys stay, because old records remain signed with them. A new witness key comes with a new name
(`…/auditor/v2`, `…/latam/v2`) and joins the witness's file, as the next section describes.
`signers.json` is the exception, because it is not a key but a current policy: it
always states who may sign a release now, and the release evidence archived under
`data/v1/cia/releases/` keeps the identity that was valid when the release was judged (its
`verdict.json` records it).

## Rotating a witness key

A witness's file lists every key the witness has signed with, one per line: the current key first,
then the ones it replaced. Blank lines are ignored. Before a rotation the file is the single line it
has always been:

```
witness.diagnos.health/latam/v1+<key hash>+<base64(algorithm ‖ public key)>
```

After it, the new key is added above the old one, which stays:

```
witness.diagnos.health/latam/v2+<key hash>+<base64(algorithm ‖ public key)>
witness.diagnos.health/latam/v1+<key hash>+<base64(algorithm ‖ public key)>
```

**Old records keep verifying because a signature is matched to a key by its name and key hash, not by
its place in the file.** A record written before the rotation names `…/latam/v1` and that key's
hash, and the old key is still listed; a record written after it names `…/latam/v2`. Nothing already
published has to be signed again, and a key stays listed for as long as any record it signed exists,
which is forever: removing it makes those records fail. A file with a single key reads exactly as it
did before.

The verifier refuses a file that is not what this section describes, so that a mistake is a failure
and never a quiet skip:

- every key belongs to the same witness: the names are the same except for the version at the end
  (`…/latam/v1`, `…/latam/v2`), so the key of another witness listed by mistake is refused;
- no key is listed twice (the same name and key hash);
- every line is a key in the form above: no comments, no text around it, no two keys on one line.

A key listed in one witness's file never verifies another witness's signatures: Europe's keys are
only ever offered for Europe's records and Latin America's for Latin America's. As with every change
in this folder, a rotation is a reviewed pull request, and it re-checks the whole record before it is
merged. Anything else that reads these files should do the same as the verifier: read them line by
line, take the first key as the current one, and match a signature by name and key hash.

## Copies outside GitHub

A key read from this repository only proves the repository agrees with itself. The same keys should
be published where someone who distrusts GitHub, or this repository, can compare them: the logs
themselves (every checkpoint at `https://transparency.diagnos.health/<log>/v1/checkpoint` names its
key), diagnos' website, and its applications' transparency pages.
