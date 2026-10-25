# Time-stamping authorities

`<provider>.pem` holds the trust anchors of each RFC 3161 authority the witness uses, in PEM: the
same roots the witness itself trusts (`apps/auditor/internal/tsa/anchors` in the diagnos monorepo).
The tokens carry their own signing and intermediate certificates, so the root is all
`openssl ts -verify -CAfile` needs.

The witness tries the authorities in this order and moves to the next on any error, timeout or
invalid answer:

| `provider` | Service URL | Anchor in `<provider>.pem` | SHA-256 fingerprint | Second source |
| --- | --- | --- | --- | --- |
| `freetsa` | `https://freetsa.org/tsr` | `CN=www.freetsa.org, OU=Root CA, O=Free TSA` | `A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC` | <https://freetsa.org/files/cacert.pem> (not in browser trust stores) |
| `digicert` | `http://timestamp.digicert.com` | `CN=DigiCert Trusted Root G4` | `55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88` | Mozilla / OS trust store |
| `sectigo` | `http://timestamp.sectigo.com` | `CN=USERTrust RSA Certification Authority` (the tokens carry `Sectigo Public Time Stamping Root R46` cross-signed by it) | `E7:93:C9:B0:2F:D8:AA:13:E2:1C:31:22:8A:CC:B0:81:19:64:3B:74:9C:89:89:64:B1:74:6D:46:C3:D4:CB:D2` | Mozilla / OS trust store |
| `globalsign` | `http://timestamp.globalsign.com/tsa/r6advanced1` | `CN=GlobalSign, OU=GlobalSign Root CA - R6` (via `GlobalSign Timestamping Root R45`) | `2C:AB:EA:FE:37:D0:6C:A2:2A:BA:73:91:C0:03:3D:25:98:29:52:C4:53:64:73:49:76:3A:3A:B5:AD:6C:CF:69` | Mozilla / OS trust store |
| `certum` | `http://time.certum.pl` | `CN=Certum Trusted Network CA` and `CN=Certum Trusted Network CA 2` (the tokens carry CA 2 cross-signed by the first) | `5C:58:46:8D:55:F5:8E:49:7E:74:39:82:D2:B5:00:10:B6:D1:65:37:4A:CF:83:A7:D4:A3:2D:B7:68:C4:40:8E` and `B6:76:F2:ED:DA:E8:77:5C:D3:6C:B0:F6:3C:D1:D4:60:39:61:F4:9E:62:65:BA:01:3A:2F:03:07:B6:D0:B8:04` | Mozilla / OS trust store |
| `apple` | `http://timestamp.apple.com/ts01` | `CN=Apple Root CA` | `B0:B1:73:0E:CB:C7:FF:45:05:14:2C:49:F1:29:5E:6E:DA:6B:CA:ED:7E:2C:68:C5:BE:91:B5:A1:10:01:F0:24` | <https://www.apple.com/certificateauthority/> |

Each fingerprint above was checked on 2026-10-25 against the second source listed (the operating
system's Mozilla-derived trust store, FreeTSA's own site over HTTPS, Apple's published fingerprint),
and each anchor verifies a real token from its authority.

In October 2026 Apple's authority still signs with SHA-1, which the witness refuses, so in practice
its tokens never appear; the anchor is there so the refusal is reported for the right reason.

The authorities answer over plain HTTP on purpose: a token is signed, so the transport adds nothing,
and the witness checks every token (status, imprint, nonce, time, signature) before writing it.

## Adding or replacing a root

Download the root from the authority's own site (not from a mirror), convert it to PEM if needed
(`openssl x509 -inform DER -in root.crt -out <provider>.pem`; for a `.p7c`,
`openssl pkcs7 -inform DER -in root.p7c -print_certs`), and check its SHA-256 fingerprint
(`openssl x509 -in <provider>.pem -noout -fingerprint -sha256`) against a second source, such as your
operating system's trust store or the authority's published fingerprint. Then check it against a
real token:

```sh
openssl ts -verify -digest "$(jq -r .imprint data/v1/timestamps/…/HHZ.json)" \
  -in data/v1/timestamps/…/HHZ.tsr -CAfile keys/tsa/<provider>.pem
```

Commit the file in a pull request that names both sources of the fingerprint. Roots are never
removed while records signed under them exist.
