package check

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// summaries cross-checks the files that summarise records (state.json,
// latest.json, the month indexes) against the records themselves. Readers
// start from the summaries; this is what keeps them honest.
type summaries struct {
	src      record.Source
	tree     *tree
	witness  map[string][]*record.Witness
	hours    []*record.Timestamp
	findings []*record.Finding
}

func (s *summaries) check() []*Report {
	var out []*Report
	if s.tree.state {
		out = append(out, s.state())
	}
	if s.tree.latest {
		out = append(out, s.latest())
	}
	for _, p := range s.tree.indexes {
		out = append(out, s.index(p))
	}
	return out
}

func (s *summaries) newest(log string) *record.Witness {
	list := s.witness[log]
	if len(list) == 0 {
		return nil
	}
	return list[len(list)-1]
}

func (s *summaries) lastHour() *record.Timestamp {
	if len(s.hours) == 0 {
		return nil
	}
	return s.hours[len(s.hours)-1]
}

func (s *summaries) state() *Report {
	r := &Report{Subject: "data/v1/state.json"}
	var st record.State
	if !decodeInto(s.src, r.Subject, "state/v1", &st, r) {
		return r
	}
	for _, log := range sortedKeys(s.witness) {
		w, got := s.newest(log), st.Logs[log]
		if w == nil {
			continue
		}
		want := record.StateLog{Origin: w.Origin, Size: w.Checkpoint.Size, Root: w.Checkpoint.Root, Record: recordPath(w), WitnessedAt: w.WitnessedAt}
		expect(r, "log "+log, got == want, "says %+v, the newest record is %+v", got, want)
	}
	expect(r, "logs", len(st.Logs) == len(s.witness), "lists %d logs, there are records for %d", len(st.Logs), len(s.witness))

	last := s.lastHour()
	switch {
	case last == nil:
		expect(r, "timestamp", st.Timestamp == nil, "points at %v, but there are no hourly records", st.Timestamp)
	case st.Timestamp == nil:
		r.fail("timestamp", "is null, the newest hourly record is %s", last.Hour)
	default:
		p := record.TimestampPath(mustTime(last.Hour))
		data, _ := s.src.Read(p)
		want := record.StateTimestamp{Hour: last.Hour, Record: p, SHA256: sum(data)}
		expect(r, "timestamp", *st.Timestamp == want, "says %+v, the newest hourly record is %+v", *st.Timestamp, want)
	}
	return r
}

func (s *summaries) latest() *Report {
	r := &Report{Subject: "data/v1/latest.json"}
	var l record.Latest
	if !decodeInto(s.src, r.Subject, "latest/v1", &l, r) {
		return r
	}
	for _, log := range sortedKeys(s.witness) {
		w := s.newest(log)
		if w == nil {
			continue
		}
		got, ok := l.Logs[log]
		var prev *uint64
		if w.Previous != nil {
			prev = &w.Previous.Size
		}
		match := ok && got.Origin == w.Origin && got.URL == w.URL && got.Size == w.Checkpoint.Size &&
			got.Root == w.Checkpoint.Root && got.Record == recordPath(w) && got.WitnessedAt == w.WitnessedAt &&
			equalPtr(got.PreviousSize, prev) && got.CheckedAt >= got.WitnessedAt && l.UpdatedAt >= got.CheckedAt
		expect(r, "log "+log, match, "does not describe the newest record %s", recordPath(w))
		expect(r, "witness", l.Witness == w.Cosignature, "names %+v, the records are cosigned by %+v", l.Witness, w.Cosignature)
	}
	expect(r, "logs", len(l.Logs) == len(s.witness), "lists %d logs, there are records for %d", len(l.Logs), len(s.witness))

	if last := s.lastHour(); last == nil {
		expect(r, "timestamp", l.Timestamp == nil, "is set, but there are no hourly records")
	} else {
		want := record.LatestTimestamp{Hour: last.Hour, Record: record.TimestampPath(mustTime(last.Hour)), Imprint: last.Imprint}
		if last.Token != nil {
			want.Token = &record.LatestToken{Provider: last.Token.Provider, GenTime: last.Token.GenTime, File: last.Token.File}
		}
		expect(r, "timestamp", l.Timestamp != nil && equalLatestTimestamp(*l.Timestamp, want),
			"does not describe the newest hourly record %s", want.Record)
	}

	var wantFindings []record.FindingSummary
	for _, f := range s.findings {
		wantFindings = append(wantFindings, summaryOf(f))
	}
	slices.Reverse(wantFindings) // newest first
	expect(r, "findings", slices.Equal(l.Findings, wantFindings), "lists %d findings, there are %d", len(l.Findings), len(wantFindings))

	var months []string
	for _, p := range s.tree.indexes {
		month := strings.TrimSuffix(strings.TrimPrefix(p, "data/v1/index/"), ".json") // "2026/10"
		months = append(months, strings.Replace(month, "/", "-", 1))
	}
	slices.Reverse(months)
	expect(r, "months", slices.Equal(l.Months, months), "lists %v, the indexes are %v", l.Months, months)
	return r
}

func (s *summaries) index(path string) *Report {
	r := &Report{Subject: path}
	var ix record.Index
	if !decodeInto(s.src, path, "index/v1", &ix, r) {
		return r
	}
	if record.IndexPath(mustTime(ix.Month+"-01T00:00:00Z")) != path {
		r.fail("month", "%s does not belong at %s", ix.Month, path)
		return r
	}

	for _, log := range sortedKeys(s.witness) {
		var want []record.IndexEntry
		for _, w := range s.witness[log] {
			if w == nil || monthOf(w.WitnessedAt) != ix.Month {
				continue
			}
			var prev *uint64
			if w.Previous != nil {
				prev = &w.Previous.Size
			}
			want = append(want, record.IndexEntry{At: w.WitnessedAt, Size: w.Checkpoint.Size, Prev: prev, Root: w.Checkpoint.Root, Record: recordPath(w)})
		}
		expect(r, "log "+log, slices.EqualFunc(ix.Logs[log], want, equalEntry),
			"has %d entries, the month has %d records", len(ix.Logs[log]), len(want))
	}
	for log := range ix.Logs {
		expect(r, "log "+log, s.witness[log] != nil || len(ix.Logs[log]) == 0, "is listed but has no records")
	}

	var want []record.IndexTimestamp
	for _, h := range s.hours {
		if h == nil || monthOf(h.Hour) != ix.Month {
			continue
		}
		p := record.TimestampPath(mustTime(h.Hour))
		data, _ := s.src.Read(p)
		e := record.IndexTimestamp{Hour: h.Hour, Record: p, SHA256: sum(data), Imprint: h.Imprint}
		if h.Subject.Prev != nil {
			e.Prev = &h.Subject.Prev.SHA256
		}
		if h.Token != nil {
			e.Provider, e.GenTime = &h.Token.Provider, &h.Token.GenTime
		}
		want = append(want, e)
	}
	expect(r, "timestamps", slices.EqualFunc(ix.Timestamps, want, equalIndexTimestamp),
		"has %d entries, the month has %d hourly records", len(ix.Timestamps), len(want))

	var wantFindings []record.FindingSummary
	for _, f := range s.findings {
		if monthOf(f.DetectedAt) == ix.Month {
			wantFindings = append(wantFindings, summaryOf(f))
		}
	}
	expect(r, "findings", slices.Equal(ix.Findings, wantFindings), "has %d findings, the month has %d", len(ix.Findings), len(wantFindings))
	return r
}

func decodeInto(src record.Source, path, schema string, v any, r *Report) bool {
	data, err := src.Read(path)
	if err == nil {
		err = record.Decode(data, schema, v)
	}
	if err != nil {
		r.fail("format", "%v", err)
		return false
	}
	return true
}

func expect(r *Report, name string, ok bool, format string, args ...any) {
	if ok {
		r.pass(name, "matches the records")
	} else {
		r.fail(name, format, args...)
	}
}

func summaryOf(f *record.Finding) record.FindingSummary {
	return record.FindingSummary{Log: f.Log, Kind: f.Kind, DetectedAt: f.DetectedAt,
		Record: record.FindingPath(f.Log, mustTime(f.DetectedAt)), Summary: f.Summary}
}

func mustTime(s string) time.Time {
	t, err := record.ParseTime(s)
	if err != nil {
		panic(fmt.Sprintf("check: unparsed time %q reached the summaries", s))
	}
	return t
}

func equalPtr[T comparable](a, b *T) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func equalEntry(a, b record.IndexEntry) bool {
	return a.At == b.At && a.Size == b.Size && equalPtr(a.Prev, b.Prev) && a.Root == b.Root && a.Record == b.Record
}

func equalIndexTimestamp(a, b record.IndexTimestamp) bool {
	return a.Hour == b.Hour && a.Record == b.Record && a.SHA256 == b.SHA256 && a.Imprint == b.Imprint &&
		equalPtr(a.Prev, b.Prev) && equalPtr(a.Provider, b.Provider) && equalPtr(a.GenTime, b.GenTime)
}

func equalLatestTimestamp(a, b record.LatestTimestamp) bool {
	return a.Hour == b.Hour && a.Record == b.Record && a.Imprint == b.Imprint && equalPtr(a.Token, b.Token)
}
