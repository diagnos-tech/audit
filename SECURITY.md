# Security policy

This repository is the public record of the confidentiality, integrity and availability of diagnos,
and of the witness that watches its transparency logs. Its value is that anyone can catch a log, the
witness, the auditor, or diagnos misbehaving. Reports that help with that are welcome, and the ones
that could be abused before they are fixed are handled privately.

## Reporting privately

**Do not open a public issue for a vulnerability.** Report it through GitHub Security Advisories:
<https://github.com/diagnos-tech/audit/security/advisories/new> (the repository's **Security** tab,
then **Report a vulnerability**).

Please include what you ran, its full output, the commit you checked out (`git rev-parse HEAD`), and
where your keys came from. We aim to acknowledge a report within five working days and to tell you
within ten whether we consider it a vulnerability, and we credit reporters unless asked not to.

## What to report privately

- **The verifier accepts something it should reject**, or rejects something valid: a note,
  signature, cosignature, consistency proof, tile, timestamp token or file that `tools/verify`
  judges differently from the specs (C2SP signed-note, tlog-checkpoint, tlog-cosignature,
  tlog-tiles; RFC 9162; RFC 3161; RFC 8785).
- **A release the auditor accepted that cosign rejects**: a service shown as *verified* whose
  `manifest.json` and bundles in `data/v1/cia/releases/` do not pass the `cosign verify-blob` and
  `cosign verify-blob-attestation` commands of [VERIFY.md](VERIFY.md#11-verify-a-release-with-cosign)
  with the identity in `keys/signers.json`, or whose served files differ from the signed manifest.
- **A day or a service shown green that the records say is not**: a view (`data/v1/cia/`) that
  `go run ./tools/verify cia` accepts but whose colours do not follow from the run records and the
  rules in VERIFY.md, or a code that maps to the wrong level.
- **The two copies of the record disagreeing on a fact.** The auditor publishes the same files to
  this repository and to a public bucket; a file that differs between them (compare
  `https://raw.githubusercontent.com/diagnos-tech/audit/develop/<path>` with the same path on the
  bucket), or a record present on one and missing on the other, means one copy was changed or
  one write failed silently.
- **The incident pipeline losing or altering an incident**: a declaration in `incidents/` that
  `go run ./tools/verify incidents` accepts as published but that does not reach
  `data/v1/cia/incidents.json` with the same text, severity, services, categories and dates, one
  that is published although its file says `publish: false`, or an edit or deletion of a
  declaration that leaves no trace in the snapshots; and, for automatic incidents, a lasting
  failure that `go run ./tools/verify cia` does not flag as lacking an incident, or an event that
  was rewritten.
- **A false red that the record should have shown as neutral**, or the opposite: a run in which the
  auditor's own network failed (the control probe and every service failed together) recorded as
  an outage instead of `vantage`, or a real outage hidden as one.
- **A weakness in how the witness, the auditor or the logs work** that would let one of them
  misbehave without this record showing it.

## What to report in public

- **A real record that does not verify.** That is a finding about diagnos, not a vulnerability in
  this repository, and it is public by nature: open an issue with the command and its output, and
  keep a copy of the files as you got them. If you believe it also reveals an exploitable weakness,
  report privately first.
- Bugs in the documentation or the tools that do not affect a verification outcome.

## Findings

When the witness records a finding (`data/v1/<log>/findings/`), the evidence is already public: two
checkpoints signed by the log that cannot both be honest. diagnos treats a finding as a security
incident: the witness stops cosigning the affected log, and the incident and its resolution are
announced publicly. A finding is never deleted or edited; the record keeps it permanently.

## Out of scope

- The **example keys and data** under `examples/` (including the example incidents and release
  evidence). They are derived from public seeds on purpose and protect nothing.
- Vulnerabilities in Tessera, `transparency-dev`, OpenSSL, Go or the time-stamping authorities:
  report those upstream (and tell us if this record is affected).
- The availability of GitHub, GitHub Pages, the public bucket or the time-stamping authorities. An
  hour without a token is recorded as such and is not a vulnerability.
- The status page's own code: it is not in this repository.
- What the record says it does **not** prove: a leak nobody declared, an outage shorter than five
  minutes, a user who could not reach a service, a Worker running a script other than the one it
  reports. These limits are documented in the [README](README.md); a report that they exist is not
  a vulnerability (a way to hide them from the record is).
- Vulnerabilities in Sigstore (Fulcio, Rekor) or cosign: report those upstream.

## Supported versions

Only the current `develop` branch. Data formats are versioned
(`schemas/v1`); a format change that is not backward compatible starts `v2` alongside, and the
tools keep reading `v1`.
