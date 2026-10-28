package check

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// tree is every file under data/v1 of a local repository, by kind.
type tree struct {
	witness    map[string][]string // log → paths, oldest first
	timestamps []string
	tokens     []string
	findings   []string
	indexes    []string
	state      bool
	latest     bool
	cia        ciaTree
	strangers  []string // files that have no place under data/v1
}

// All checks every file under data/v1 of the repository at dir: each record
// on its own, the chains between them (every witness record links to the
// one before it, every hourly record to the hour before it), and the
// summaries (state.json, latest.json, the month indexes) against the
// records they summarise.
func All(dir string, src record.Source, keys *Keyring, opts TimestampOptions) ([]*Report, error) {
	return AllWith(dir, src, keys, opts, CIAOptions{})
}

// AllWith is All with options for the CIA record (see CIAOptions).
func AllWith(dir string, src record.Source, keys *Keyring, opts TimestampOptions, ciaOpts CIAOptions) ([]*Report, error) {
	t, err := walk(dir)
	if err != nil {
		return nil, err
	}
	var reports []*Report
	for _, p := range t.strangers {
		r := &Report{Subject: p}
		r.fail("layout", "this file has no place under data/v1 (see the contract in README.md)")
		reports = append(reports, r)
	}

	recs := map[string][]*record.Witness{}
	logs := sortedKeys(t.witness)
	for _, log := range logs {
		for i, p := range t.witness[log] {
			rec, r := Witness(src, keys, p)
			recs[log] = append(recs[log], rec)
			if rec != nil {
				linkCheck(r, "chain", i, rec.Previous == nil, prevRecord(rec), t.witness[log])
			}
			reports = append(reports, r)
		}
	}

	var hours []*record.Timestamp
	referenced := map[string]bool{}
	for i, p := range t.timestamps {
		rec, r := Timestamp(src, p, opts)
		hours = append(hours, rec)
		if rec != nil {
			prev := ""
			if rec.Subject.Prev != nil {
				prev = rec.Subject.Prev.Record
			}
			linkCheck(r, "hour chain", i, rec.Subject.Prev == nil, prev, t.timestamps)
			checkSubjectIsLatest(rec, recs, r)
			if rec.Token != nil {
				referenced[rec.Token.File] = true
			}
		}
		reports = append(reports, r)
	}
	for _, p := range t.tokens {
		if !referenced[p] {
			r := &Report{Subject: p}
			r.fail("layout", "no hourly record refers to this token")
			reports = append(reports, r)
		}
	}

	var findings []*record.Finding
	for _, p := range t.findings {
		f, r := Finding(src, keys, p)
		if f != nil {
			findings = append(findings, f)
		}
		reports = append(reports, r)
	}

	s := summaries{src: src, tree: t, witness: recs, hours: hours, findings: findings}
	reports = append(reports, s.check()...)
	if !t.cia.empty() {
		reports = append(reports, CIA(src, &t.cia, ciaOpts)...)
	}
	return reports, nil
}

// linkCheck verifies that the i-th record of a chain points at the (i-1)-th:
// no gaps, no forks, nothing skipped.
func linkCheck(r *Report, name string, i int, first bool, prev string, paths []string) {
	switch {
	case i == 0 && first:
		r.pass(name, "first of its chain")
	case i == 0:
		r.fail(name, "links to %s, but it is the oldest file present", prev)
	case first:
		r.fail(name, "claims to be first, but %s precedes it", paths[i-1])
	case prev != paths[i-1]:
		r.fail(name, "links to %s, but the file before it is %s", prev, paths[i-1])
	default:
		r.pass(name, "follows %s", paths[i-1])
	}
}

func prevRecord(w *record.Witness) string {
	if w.Previous == nil {
		return ""
	}
	return w.Previous.Record
}

// checkSubjectIsLatest: the hour's subject must name, for each log, the
// newest record witnessed before the hour began (the hourly run cannot
// start earlier, so it knew about all of them).
func checkSubjectIsLatest(rec *record.Timestamp, recs map[string][]*record.Witness, r *Report) {
	hour, _ := record.ParseTime(rec.Hour)
	for log, list := range recs {
		var newest *record.Witness
		for _, w := range list {
			if w == nil {
				continue
			}
			if at, _ := record.ParseTime(w.WitnessedAt); at.Before(hour) {
				newest = w
			}
		}
		named, ok := rec.Subject.Logs[log]
		switch {
		case newest == nil:
			continue
		case !ok:
			r.fail("subject "+log, "missing, although %s was witnessed before the hour", recordPath(newest))
		case named.Record < recordPath(newest):
			r.fail("subject "+log, "names %s, but %s is newer and before the hour", named.Record, recordPath(newest))
		}
	}
}

func walk(dir string) (*tree, error) {
	t := &tree{witness: map[string][]string{}}
	base := filepath.Join(dir, "data", "v1")
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch record.Kind(rel) {
		case "witness":
			log := strings.Split(rel, "/")[2]
			t.witness[log] = append(t.witness[log], rel)
		case "timestamp":
			t.timestamps = append(t.timestamps, rel)
		case "token":
			t.tokens = append(t.tokens, rel)
		case "finding":
			t.findings = append(t.findings, rel)
		case "index":
			t.indexes = append(t.indexes, rel)
		case "state":
			t.state = true
		case "latest":
			t.latest = true
		case "cia-run":
			t.cia.runs = append(t.cia.runs, rel)
		case "cia-incidents":
			t.cia.snapshots = append(t.cia.snapshots, rel)
		case "cia-day":
			t.cia.days = append(t.cia.days, rel)
		case "cia-summary":
			t.cia.summary = true
		case "cia-latest":
			t.cia.latest = true
		case "cia-incidents-view":
			t.cia.view = true
		case "cia-changes":
			t.cia.changes = true
		case "cia-changes-recent":
			t.cia.recent = true
		case "cia-incident-event":
			t.cia.events = append(t.cia.events, rel)
		case "sync":
			t.cia.sync = true
		case "release-verdict", "release-manifest", "release-evidence":
			if dir := path.Dir(rel); !slices.Contains(t.cia.releaseDirs, dir) {
				t.cia.releaseDirs = append(t.cia.releaseDirs, dir)
			}
		default:
			t.strangers = append(t.strangers, rel)
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		if _, statErr := os.Stat(base); errors.Is(statErr, fs.ErrNotExist) {
			return t, nil // nothing published yet
		}
	}
	// WalkDir visits in lexical order, which for these names is time order.
	return t, err
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// monthOf extracts the month of a record from its RFC 3339 time.
func monthOf(t string) string {
	parsed, err := record.ParseTime(t)
	if err != nil {
		return ""
	}
	return parsed.Format("2006-01")
}
