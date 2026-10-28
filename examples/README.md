# Example data: not real records

Everything under this directory is **made up**. It exists so the tools and the docs can be
tried before (and independently of) the real record, with every situation the real record can show.

- It is written by [`tools/genexamples`](../tools/genexamples): `go run ./tools/genexamples`,
  deterministically, from fixed public seeds. CI fails if the committed copy differs from what the
  generator writes.
- Every key is derived from a seed printed in the generator's source. The keys protect nothing and
  must never be copied into [`keys/`](../keys).
- Every name uses the reserved `.example` domain (`transparency.example/audit/v1`,
  `witness.example/auditor/v1`, `Example TSA`), so an example can never pass for a real record.

The layout mirrors the repository root, so every command works with `-root examples`:

| Path | What it shows |
| --- | --- |
| `data/v1/audit/witness/…` | the audit log over 27 hours, growing in most business-hours windows and rarely at night; no record between 05:00 and 05:20 on 1 October (the auditor did not run) |
| `data/v1/signs/witness/…` | the signatures log, growing a few times an hour |
| `data/v1/signs/findings/2026/10/01/133507Z.json` | an **equivocation**: the log signed a second root for a size the witness had cosigned; the witness stops cosigning `signs` |
| `data/v1/timestamps/2026/09/30/18Z.*` | the first authority failed; the backup authority's token |
| `data/v1/timestamps/2026/10/01/03Z.json` | every authority failed: a record with `"token": null`, still linked into the chain |
| `data/v1/timestamps/2026/10/01/05Z.json` | hour 05 was stamped late, by the first run after the gap |
| `data/v1/timestamps/…` (`subject.cia`) | every hour pins the run record that stamped it |
| `data/v1/index/2026/09.json`, `2026/10.json` | the records span a month boundary |
| `data/v1/cia/runs/…` | one run record per five-minute slot from 2026-09-30 11:00Z to 2026-10-01 14:20Z, chained, each with its vantage (`scaleway:fr-par`), its control probe and the timings of every `/healthz` attempt; the oldest links a record that is not here (the files are a slice of a longer history); the run of 09:00Z on 1 October is a vantage failure |
| `data/v1/cia/incidents/YYYY/MM/DD/…` | four snapshots of the declared incidents: a declaration made by mistake (17:45Z), the example incident declared while open (18:15Z), resolved with the mistake withdrawn (09:35Z), and a postmortem added (11:55Z) |
| `data/v1/cia/incidents/events/…` | the incidents the auditor opened by itself, one file per step: two outages and a served-bytes mismatch of the scripted history, the `vault` timeout of 1 October, and the `status` integrity incident the `signs` equivocation opened (updated when the log was halted, never resolved) |
| `data/v1/cia/incidents.json` | the incident list: the declared incidents of the newest snapshot and the automatic ones, each in its latest state, with the postmortems that relate to them |
| `data/v1/cia/changes.json`, `changes-recent.json` | the change events of the window, newest first, and the first 30 of them: every kind occurs |
| `data/v1/cia/releases/…` | the verdict and manifest of each service's release; the Sigstore bundles are not archived (examples have no real signing certificate) |
| `data/v1/cia/days/…` | one day file for every day that had a run: 2026-07-04 to 2026-10-01, minus two days the auditor was down; each service has its `/healthz` latency in every slot and the median and 95th percentile of them |
| `data/v1/cia/summary.json`, `latest.json`, `data/v1/sync.json` | the 90-day summary (first run 2026-07-04) with each service's daily 95th percentile latency, the headline after the 14:20Z run, the mirror cursor |
| `incidents/` | the incident files the snapshots are made from: the published example, a postmortem that `relates` to an automatic incident, and the unpublished template (proves it is filtered) |
| `keys/` | example log, witness and authority keys (the authorities' roots are example CAs); `signers.json` pins the example build identities the example verdicts name |

What the CIA data shows (all of it invented). The services are `frontend`, `vault`, `sign` and `status`
(hosts under `.diagnos.example`, all released by the same example pipeline); the transparency logs
`audit` and `signs` are attached to `status`:

- **Availability.** Mostly green with yellow days (slow answers) and three red days: `vault` unreachable
  for 25 minutes on 2026-08-12 and for 20 minutes (03:10Z to 03:30Z) on 2026-10-01, `sign` for 25
  minutes on 2026-09-03 (a day is red from three failed slots). The auditor
  itself did not run on 2026-07-19 and 2026-08-23 (grey in every row) or on the morning of 2026-09-30.
- **Integrity.** `frontend` runs a build deployed by hand, without evidence, from 2026-09-27 until a
  signed release is found at 10:00Z on 2026-10-01 (pending for one slot, then verified);
  `sign` served a file that differed from its signed release on 2026-08-27 (red); `status` turns red
  at 13:35Z on 2026-10-01, when the witness records the `signs` equivocation, and stays red (halted).
- **Latency.** Each healthy answer has a latency (vault 80 to 250 ms, frontend 60 to 150, sign 160 to
  300, status 100 to 200) split into name lookup, connection, TLS and wait for the first byte; a slow
  answer is mostly the wait. A timeout has no latency, only the 8 s it took; a refused connection has
  only the name lookup. The daily 95th percentile steps up for a week after the `vault` release of
  2026-08-04, for four days on `sign` in September and on 2026-07-21 and 22 on `frontend`.
- **Confidentiality.** The published incident (category C) colours `sign` yellow from 16:40Z on
  2026-09-30 (when it started, although it was declared at 18:10Z) until 09:30Z the next day.
- **Incidents.** Declared incidents colour the dimensions of their categories (C, I, A) on their
  services; the auditor's own incidents colour availability or integrity, and cover exactly the slots
  that failed. The `vault` outage of 03:10Z is the incident `2026-10-01-auto-vault-a-0310`, opened at
  03:20Z, after three failed slots, and resolved at 03:35Z, after two good ones; the declared
  postmortem `relates` to it and colours the same slots.
- **Late data.** The auditor did not run between 05:00Z and 05:20Z on 2026-10-01: the record is
  delayed, grey, and nothing is called an outage. At 09:00Z the auditor's own network failed (the
  control probe and every service probe failed): every network check of that run is `vantage`, grey,
  and opens no incident.
- **Changes.** `changes.json` lists what happened in the window: levels changing (after three slots
  to get worse, two to get better), a release verified, a witness finding, incidents declared, opened,
  updated, resolved and withdrawn, the delayed record and its return, and the vantage failure.

The CIA files are derived by the same code `verify cia` recomputes them with. The 88 days before
the window have day files and a summary but no run records (they are scripted in
[`tools/genexamples`](../tools/genexamples)), so `verify cia` accepts them as a slice and
`verify cia -complete` rejects them: with the whole history, the oldest run record must be the first.

Check it with:

```sh
go run ./tools/verify all -root examples -openssl
go run ./tools/verify incidents examples/incidents/*.md
```
