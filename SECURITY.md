# Security policy

This repository is the public record of a transparency-log witness. Its value is that anyone can
catch a log, the witness, or diagnos misbehaving. Reports that help with that are welcome, and the
ones that could be abused before they are fixed are handled privately.

## Reporting privately

**Do not open a public issue for a vulnerability.** Report it through GitHub Security Advisories:
<https://github.com/diagnos-tech/audit/security/advisories/new> (the repository's **Security** tab,
then **Report a vulnerability**).

Please include what you ran, its full output, the commit you checked out (`git rev-parse HEAD`), and
where your keys came from. We aim to acknowledge a report within five working days and to tell you
within ten whether we consider it a vulnerability, and we credit reporters unless asked not to.

## What to report privately

- **The verifier accepts something it should reject**, or rejects something valid: a note,
  signature, cosignature, consistency proof, tile, timestamp token or file that `tools/verify` (or
  the page's in-browser check) judges differently from the specs (C2SP signed-note, tlog-checkpoint,
  tlog-cosignature, tlog-tiles; RFC 9162; RFC 3161; RFC 8785).
- **The page can be made to show something that is not in the data**, or to run anything: for
  example through a crafted link, file name or data value.
- **A weakness in how the witness or the logs work** that would let one of them misbehave without
  this record showing it.

## What to report in public

- **A real record that does not verify.** That is a finding about diagnos, not a vulnerability in
  this repository, and it is public by nature: open an issue with the command and its output, and
  keep a copy of the files as you got them. If you believe it also reveals an exploitable weakness,
  report privately first.
- Bugs in the page, the documentation or the tools that do not affect a verification outcome.

## Findings

When the witness records a finding (`data/v1/<log>/findings/`), the evidence is already public: two
checkpoints signed by the log that cannot both be honest. diagnos treats a finding as a security
incident: the witness stops cosigning the affected log, and the incident and its resolution are
announced publicly. A finding is never deleted or edited; the record keeps it permanently.

## Out of scope

- The **example keys and data** under `examples/`. They are derived from public seeds on purpose and
  protect nothing.
- Vulnerabilities in Tessera, `transparency-dev`, OpenSSL, Go or the time-stamping authorities:
  report those upstream (and tell us if this record is affected).
- The availability of GitHub Pages or of the time-stamping authorities. An hour without a token is
  recorded as such and is not a vulnerability.

## Supported versions

Only the current `develop` branch. Data formats are versioned (`schemas/v1`); a format change that
is not backward compatible starts `v2` alongside, and the tools keep reading `v1`.
