# Declaring an incident

Some things cannot be measured from outside: the auditor cannot see a leak. What this record shows
for them is what diagnos has **declared**. When diagnos learns that data was exposed, that
something changed or ran that should not have, or that a service was unusable, it can declare it
here, in public, and the declaration colours the affected services from the moment it started until
it was resolved.

A declaration is a Markdown file in this folder, added by a reviewed pull request. Incidents also
come from the other side: when the auditor's own measurements fail in a lasting way it opens
an **automatic** incident itself (see the end of this page). Humans never write those.

## How to declare one

1. Copy [`2026-10-27-example.md`](2026-10-27-example.md) to `incidents/<YYYY-MM-DD>-<slug>.md`. The
   date is the day you declare the incident; the slug is lowercase words joined by hyphens, and
   must not start with `auto-` (that prefix belongs to automatic incidents).
2. Change every field, set `publish: true`, and write both language bodies.
3. Check it: `go run ./tools/verify incidents incidents/<your-file>.md`. It prints the rule you
   broke, or whether the file is published.
4. Open a pull request. CI runs the same check. Once merged, the auditor reads the folder on its
   next run (within five minutes) and the status page shows the incident.

To update an incident, edit its file in a new pull request: change `status`, add `resolved_at` when
it is resolved, extend the text. Never delete a declaration to hide it; see below for what the
record keeps.

## Categories: what kind of incident it is

`categories` says which of the three dimensions the incident touches, and it is required:

| Category | Dimension | Use it when |
| --- | --- | --- |
| `C` | confidentiality | data was exposed to someone who should not have had it |
| `I` | integrity | something changed or ran that should not have (a wrong build, altered data) |
| `A` | availability | a service was unusable |

An incident may have one, two or all three (`categories: [C, A]`). It colours **only** those
dimensions of the services it lists, and `severity` decides the colour: `low` and `medium` are
yellow, `high` and `critical` are red.

## The file

```
---
id: 2026-09-30-sign-session-ids-in-logs
title:
  en: "Signing session identifiers written to an internal log"
  pt-BR: "Identificadores de sessão de assinatura gravados num log interno"
summary:
  en: For 17 hours an internal error log kept signing session identifiers.
  pt-BR: Por 17 horas um log interno de erros guardou identificadores de sessão de assinatura.
services: [sign]
categories: [C]
severity: medium
status: resolved
declared_at: 2026-09-30T18:10:00Z
started_at: 2026-09-30T16:40:00Z
resolved_at: 2026-10-01T09:30:00Z
publish: true
---

## English

What happened, what data and which people were affected, what was done, and what changes.

## Português

O que aconteceu, que dados e quais pessoas foram afetados, o que foi feito e o que muda.
```

| Field | Meaning |
| --- | --- |
| `id` | Equal to the file name without `.md`. |
| `title`, `summary` | Plain text in both languages: a title of up to 120 characters and a summary of up to 280. |
| `services` | Between one and four of `frontend`, `vault`, `sign`, `status`, distinct, written `[vault, sign]`. |
| `categories` | Between one and three distinct values of `C`, `I`, `A`, written `[C, A]`. Required. |
| `severity` | `low`, `medium`, `high` or `critical`. |
| `status` | `investigating`, `identified`, `monitoring` or `resolved`. |
| `declared_at` | When diagnos declared it. Times are UTC, `YYYY-MM-DDTHH:MM:SSZ`, and not more than five minutes in the future. |
| `started_at` | When it began, if known. Optional; defaults to `declared_at`; never later than it. |
| `resolved_at` | When it ended. Required when `status` is `resolved`, and only then; not before `started_at`. |
| `relates` | Optional. The id of an automatic incident this declaration explains, such as `2026-10-01-auto-vault-a-0310`: a postmortem. The record links the two. |
| `publish` | `true` makes the incident count and appear. `false` is for templates and drafts: the file is still checked, then ignored. It is **not** secret, because this repository is public. |

### The exact format

The front matter is a small, strict subset of YAML, read by exactly two programs that follow the same
rules (the auditor and `tools/verify incidents`), so every rule below is enforced:

- The file is UTF-8 with LF line ends, no tabs, no byte-order mark, and at most 64 KiB.
- It starts with a line `---`, then one `key: value` line per field, then a line `---`. Each key
  appears at most once, in any order, and no other key is allowed. No blank lines, comments or
  indentation anywhere in the front matter, except the two lines under `title` and under `summary`.
- `title` and `summary` are followed by exactly two lines, indented by two spaces: `en:` and then
  `pt-BR:`, in that order.
- A text is either plain (it must not start with `- ? : , [ ] { } # & * ! | > ' " % @` or a
  backquote, must not contain `: ` or ` #`, and must not end with `:` or a space) or a JSON string in
  double quotes on one line. When in doubt, quote it.
- `services` and `categories` are lists in square brackets with items separated by a comma and a
  space. `publish` is `true` or `false`; `resolved_at` may be `null`.
- `relates`, when present, is the id of an automatic incident. Its shape is checked when the file is
  read; that the incident exists is checked against the record (`go run ./tools/verify cia`).
- The slug of `id` (the part after the date) must not start with `auto-`.
- After the closing `---`: optional blank lines, then `## English`, a blank line, the English text,
  a blank line, `## Português`, a blank line, the Portuguese text. Each text is not empty and has at
  most 20 000 characters.

The bodies may use only `###` and `####` headings, paragraphs, lists (`- ` and `1. `, one level),
fenced code blocks, `` `code` ``, `**bold**`, `*emphasis*` and links whose address starts with
`https://`. Raw HTML, images, tables and nested lists are not rendered: they appear as plain text.

## What an incident does to the colours

A published incident affects dimension `d` of service `s` during a five-minute slot
`[t, t + 5 min)` when `s` is in `services`, the category of `d` is in `categories`, `started_at` is
before the end of the slot, and the incident is not resolved or was resolved after the start of the
slot. Its level is `warn` (yellow) for `low` and `medium`, `fail` (red) for `high` and `critical`;
when several incidents affect the same slot, the worst counts.

- **Availability and integrity** show the worse of the measurement and the incident. A declared
  major availability incident turns the slots red even if `/healthz` answered; a green measurement
  never hides an incident, and an incident never hides a failed measurement.
- **Confidentiality** is coloured only by incidents. Nothing measures it, so a green row means *no
  incident declared*, nothing more.
- **The past is recoloured.** The colours follow `started_at`, not the day of the declaration, so
  declaring an incident late still paints the days it covers. The day views are rewritten when an
  incident is declared, edited or resolved.
- **What was known stays.** Each run record keeps what the auditor knew when it ran, and each
  snapshot of the published incidents pins the Git blob of every incident file and is chained into
  the hourly timestamps. An edit or a deletion of a declaration therefore stays visible in the
  history, and `publish: false` or removing a file removes it from the status page without erasing
  that trail.
- **A broken file is loud.** If an incident file is invalid, the auditor raises an alert, keeps the
  last valid version of that file, and shows every service's confidentiality as at least yellow
  until it is fixed. CI should have caught it first.

## Automatic incidents

The auditor opens, updates and resolves incidents of its own, so a failure never depends on someone
remembering to declare it. They are not files in this folder: each change is an immutable record,
`data/v1/cia/incidents/events/YYYY/MM/DD/<id>-<seq>.json`, and the incident appears in
`data/v1/cia/incidents.json` next to the declared ones, marked `source: "auditor"`. Their ids look
like `2026-10-01-auto-vault-a-0310` (day of the start, `auto`, service, `a` or `i`, start time).

| Category | Opens | Resolves |
| --- | --- | --- |
| `A` availability | a service's measured availability is `fail` in 3 consecutive five-minute slots (15 minutes); severity `high` | 2 consecutive slots that are not failing; it covers exactly the failed slots |
| `I` integrity | an invalid release, served files that differ from the signed manifest, or a witness finding, at once; `critical` for differing files and findings | no longer failing for 2 consecutive slots; a witness finding or a halted log never resolves |
| `C` confidentiality | never: a leak cannot be detected from outside | |

A gap in the record, a late run, or a run in which the auditor's own network failed is *not
measured* and never opens an incident; it is neither counted toward a failure nor does it interrupt
one. `go run ./tools/verify cia` checks that the record obeys this policy, including that a
lasting failure that was not turned into an incident is detected.

To explain an automatic incident, declare one with `relates: <its id>` (a postmortem). It is a
normal declaration, with its own `categories`, and the automatic incident then lists it.

The folder also holds this README and `SUMMARY.md`; every other file name that does not match
`<YYYY-MM-DD>-<slug>.md` is ignored. The shipped template has `publish: false`; published examples
live only under [`examples/incidents/`](../examples/incidents) and the example data.
