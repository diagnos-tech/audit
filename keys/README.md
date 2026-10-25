# Public keys

The keys needed to check every record. They are public by nature; publishing them is the point.

| File | Key | Algorithm |
| --- | --- | --- |
| `logs/audit.vkey` | the `audit` log's checkpoint key, `transparency.diagnos.health/audit/v1` | signed-note Ed25519 (`0x01`) |
| `logs/signs.vkey` | the `signs` log's checkpoint key, `transparency.diagnos.health/signs/v1` | signed-note Ed25519 (`0x01`) |
| `witness/auditor.vkey` | the witness's key, `witness.diagnos.health/auditor/v1` | `cosignature/v1` Ed25519 (`0x04`) |
| `tsa/<provider>.pem` | each time-stamping authority's CA chain | X.509, see [tsa/README.md](tsa/README.md) |

Each `.vkey` file is one line, `<name>+<key hash>+<base64(algorithm ‖ public key)>`, followed by a
newline. [VERIFY.md](../VERIFY.md#2-decide-which-keys-to-trust) shows how to recompute the key hash
and how to compare these keys with copies obtained elsewhere.

**The log and witness keys are added when the witness goes live, by a person, in a reviewed pull
request.** Until then `logs/` and `witness/` do not exist and the tools say so instead of guessing.
The authorities' roots in `tsa/` are already here: they are public, chosen by the witness's code,
and listed with their fingerprints in [tsa/README.md](tsa/README.md). The example keys used by the
example data live in [`examples/keys`](../examples/keys) and must never be copied here.

## Rotation

A key is never edited in place. A new log key comes with a new origin (`…/v2`) and a new witness key
with a new name (`…/auditor/v2`), and gets its own file; old keys stay, because old records remain
signed with them.

## Copies outside GitHub

A key read from this repository only proves the repository agrees with itself. The same keys should
be published where someone who distrusts GitHub, or this repository, can compare them: the logs
themselves (every checkpoint at `https://transparency.diagnos.health/<log>/v1/checkpoint` names its
key), diagnos' website, and its applications' transparency pages.
