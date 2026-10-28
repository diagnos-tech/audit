package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/incidents"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// snapshot is one cia-incidents/v1 file, written by the run of its slot.
type snapshot struct {
	slot      time.Time
	path      string
	sha       string
	data      []byte
	content   *record.CIAIncidents
	incidents cia.Incidents
}

func (s *snapshot) write(w *writer) error { return w.raw(s.path, s.data) }

// The declared incidents of the examples change over the window, which gives
// four snapshots: a mistaken declaration is made (0); the example incident is
// declared while it is open (1); it is resolved and the mistaken one is
// withdrawn (2); and a postmortem for the vault outage is added (3). Run records
// keep what each run knew; the views are coloured by the last snapshot.
var snapshotSlots = []time.Time{
	time.Date(2026, 9, 30, 17, 45, 0, 0, time.UTC),
	time.Date(2026, 9, 30, 18, 15, 0, 0, time.UTC),
	time.Date(2026, 10, 1, 9, 35, 0, 0, time.UTC),
	time.Date(2026, 10, 1, 11, 55, 0, 0, time.UTC),
}

// presence says in which snapshots a published incident file is present: from
// the first index up to, not including, the second.
var presence = map[string][2]int{
	mistakenID:                            {0, 2},
	"2026-09-30-sign-session-ids-in-logs": {1, 99},
	"2026-10-01-vault-timeout-postmortem": {3, 99},
}

// readTime is when the run of a slot reads GitHub (it started a second in).
func readTime(slot time.Time) time.Time { return slot.Add(2 * time.Second) }

var (
	statusLine   = regexp.MustCompile(`(?m)^status: resolved\n`)
	resolvedLine = regexp.MustCompile(`(?m)^resolved_at: .*\n`)
)

// asFirstDeclared turns a resolved incident file into the version that was
// committed when it was declared.
func asFirstDeclared(data []byte) []byte {
	data = statusLine.ReplaceAll(data, []byte("status: identified\n"))
	return resolvedLine.ReplaceAll(data, nil)
}

type incidentFile struct {
	name string
	data []byte
}

// loadSnapshots reads <dir>/*.md and builds the snapshots. Files with publish
// false are parsed (an invalid one is an error) and left out.
func loadSnapshots(dir string) ([]*snapshot, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		return nil, err
	}
	clock := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	files := map[string]incidentFile{mistakenID: {mistakenID + ".md", []byte(mistakenText)}}
	for _, p := range paths {
		name := filepath.Base(p)
		if !incidents.IsFileName(name) {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		inc, err := incidents.Parse(name, data, clock)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if !inc.Publish {
			continue
		}
		if _, planned := presence[inc.ID]; !planned {
			return nil, fmt.Errorf("%s is published but the examples have no plan for it (presence in cia_incidents.go)", name)
		}
		files[inc.ID] = incidentFile{name, data}
	}
	var out []*snapshot
	for i, slot := range snapshotSlots {
		content := &record.CIAIncidents{
			Schema: "cia-incidents/v1", ReadAt: record.FormatTime(readTime(slot)), Incidents: []record.CIAIncident{},
			Source: record.CIAIncidentsSource{Repository: "diagnos-tech/audit", Commit: fakeHex("develop " + slot.Format(record.DayLayout)), Path: "incidents"},
		}
		for _, id := range sortedKeys(presence) {
			if p := presence[id]; i < p[0] || i >= p[1] {
				continue
			}
			f, ok := files[id]
			if !ok {
				return nil, fmt.Errorf("examples/incidents lacks %s.md", id)
			}
			data := f.data
			if id == "2026-09-30-sign-session-ids-in-logs" && i == presence[id][0] {
				if data = asFirstDeclared(f.data); string(data) == string(f.data) {
					return nil, fmt.Errorf("%s: cannot derive the first-declared version", f.name)
				}
			}
			inc, err := incidents.Parse(f.name, data, clock)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f.name, err)
			}
			content.Incidents = append(content.Incidents, inc.Snapshot(incidents.BlobHash(data)))
		}
		sort.SliceStable(content.Incidents, func(a, b int) bool {
			x, y := content.Incidents[a], content.Incidents[b]
			if x.DeclaredAt != y.DeclaredAt {
				return x.DeclaredAt > y.DeclaredAt
			}
			return x.ID < y.ID
		})
		data, err := record.Encode(content)
		if err != nil {
			return nil, err
		}
		set, err := cia.FromSnapshot(content)
		if err != nil {
			return nil, err
		}
		out = append(out, &snapshot{slot: slot, path: record.CIAIncidentsPath(slot), sha: sum(data), data: data,
			content: content, incidents: set})
	}
	return out, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// mistakenID is a declaration that was made by mistake and withdrawn: it has
// no file in examples/incidents (the file was deleted), only the snapshots that
// held it and the change events that say so.
const mistakenID = "2026-09-30-frontend-wrong-banner"

const mistakenText = `---
id: 2026-09-30-frontend-wrong-banner
title:
  en: Wrong banner on the website (declared by mistake)
  pt-BR: Banner errado no site (declarado por engano)
services: [frontend]
categories: [I]
severity: low
status: investigating
declared_at: 2026-09-30T17:40:00Z
started_at: 2026-09-30T17:20:00Z
publish: true
summary:
  en: Example data. A banner seemed to show the wrong version; it was the right one and the declaration was withdrawn.
  pt-BR: Dado de exemplo. Um banner parecia mostrar a versão errada; era a certa e a declaração foi retirada.
---

## English

**Example data.** Declared by mistake and withdrawn.

## Português

**Dado de exemplo.** Declarado por engano e retirado.
`
