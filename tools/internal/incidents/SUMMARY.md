# incidents

Reads `incidents/<id>.md` exactly as CONTRACTS §4 and INCIDENTS-CONTRACT §1 define it, so that the verifier
and the auditor accept and reject the same files.

- `incident.go` — limits, `Parse`, the snapshot item, the Git blob hash, ids of declared and automatic incidents
- `frontmatter.go` — whole-file rules and the front matter grammar
- `build.go` — the rules on the fields: ids, services, categories, relates, enums, times, publish
- `body.go` — the `## English` / `## Português` body and the heading rule
- `incident_test.go` — one case per rule, the shipped files