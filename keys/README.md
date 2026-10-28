# Public keys

The keys needed to check every record. They are public by nature; publishing them is the point.

| File | Key | Algorithm |
| --- | --- | --- |
| `logs/audit.vkey` | the `audit` log's checkpoint key, `transparency.diagnos.health/audit/v1` | signed-note Ed25519 (`0x01`) |
| `logs/signs.vkey` | the `signs` log's checkpoint key, `transparency.diagnos.health/signs/v1` | signed-note Ed25519 (`0x01`) |
| `witness/auditor.vkey` | the witness's key, `witness.diagnos.health/auditor/v1` | `cosignature/v1` Ed25519 (`0x04`) |
| `tsa/<provider>.pem` | each time-stamping authority's CA chain | X.509, see [tsa/README.md](tsa/README.md) |
| `signers.json` | for each audited service, the CI identity whose signature a release must carry | JSON, `signers/v1` ([schema](../schemas/v1/signers.schema.json)) |

Each `.vkey` file is one line, `<name>+<key hash>+<base64(algorithm ‖ public key)>`, followed by a
newline. [VERIFY.md](../VERIFY.md#2-decide-which-keys-to-trust) shows how to recompute the key hash
and how to compare these keys with copies obtained elsewhere.

**The log and witness keys are added when the witness goes live, by a person, in a reviewed pull
request.** Until then `logs/` and `witness/` do not exist and the tools say so instead of guessing.
The authorities' roots in `tsa/` are already here: they are public, chosen by the witness's code,
and listed with their fingerprints in [tsa/README.md](tsa/README.md). The example keys used by the
example data live in [`examples/keys`](../examples/keys) and must never be copied here.

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

A key is never edited in place. A new log key comes with a new origin (`…/v2`) and a new witness key
with a new name (`…/auditor/v2`), and gets its own file; old keys stay, because old records remain
signed with them. `signers.json` is the exception, because it is not a key but a current policy: it
always states who may sign a release now, and the release evidence archived under
`data/v1/cia/releases/` keeps the identity that was valid when the release was judged (its
`verdict.json` records it).

## Copies outside GitHub

A key read from this repository only proves the repository agrees with itself. The same keys should
be published where someone who distrusts GitHub, or this repository, can compare them: the logs
themselves (every checkpoint at `https://transparency.diagnos.health/<log>/v1/checkpoint` names its
key), diagnos' website, and its applications' transparency pages.
