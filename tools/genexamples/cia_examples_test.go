package main

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/check"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// rewrite decodes the data file at path, lets change edit it and writes it
// back the way the auditor does.
// The examples are a slice of a longer history, which `verify cia -complete`
// refuses: that mode is for the real record, whose oldest run is the first.
func TestCompleteModeRejectsTheExamples(t *testing.T) {
	_, dir := generateExamples(t)
	failed, _ := verifyAllWith(t, dir, check.CIAOptions{Complete: true}, false)
	all := strings.Join(failed, "\n")
	for _, want := range []string{
		"with -complete the oldest record must be the first run",
		"no run record backs this day file",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("-complete did not report %q; failures:\n%.2000s", want, all)
		}
	}
}

// The scripted history shows what it promises: green with yellow, red and
// grey days, and the states CONTRACTS §12 lists in the last two days.
func TestExampleHistoryHasEveryState(t *testing.T) {
	_, dir := generateExamples(t)
	var sum record.CIASummary
	data, err := os.ReadFile(filepath.Join(dir, record.CIASummaryPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Decode(data, "cia-summary/v1", &sum); err != nil {
		t.Fatal(err)
	}
	letters := map[string]map[byte]int{}
	for _, svc := range sum.Services {
		for _, dim := range record.Dimensions {
			if letters[dim] == nil {
				letters[dim] = map[byte]int{}
			}
			for _, l := range []byte(svc.Series(dim).Days) {
				letters[dim][l]++
			}
		}
	}
	for _, dim := range []string{"availability", "integrity"} {
		for _, l := range []byte("owf-") {
			if letters[dim][l] == 0 {
				t.Errorf("no %q day in %s", l, dim)
			}
		}
	}
	if letters["confidentiality"]['w'] != 2 || letters["availability"]['o'] < 300 {
		t.Errorf("confidentiality %v availability %v", letters["confidentiality"], letters["availability"])
	}
	if sum.To != "2026-10-01" || sum.From != "2026-07-04" || sum.FirstRun != "2026-07-04T00:00:00Z" {
		t.Errorf("window %s to %s from %s", sum.From, sum.To, sum.FirstRun)
	}

	var d record.CIADay
	data, _ = os.ReadFile(filepath.Join(dir, dayFile))
	if err := record.Decode(data, "cia-day/v1", &d); err != nil {
		t.Fatal(err)
	}
	if d.Runs[60:64] != "0000" || d.Runs[59] != '1' || d.Runs[64] != '1' {
		t.Errorf("the auditor gap of 05:00-05:15 is slots 60-63; runs around it: %q", d.Runs[58:66])
	}
	if got := d.Services["vault"].Availability[38:42]; got != "ffff" {
		t.Errorf("vault timeout 03:10-03:25 is slots 38-41: %q", got)
	}
}

// `verify cia FILE...` reports on the named files only, but derives them from
// everything else in the clone.
func TestCIAFilesFilter(t *testing.T) {
	_, dir := generateExamples(t)
	src, err := record.Open(context.Background(), nil, dir)
	if err != nil {
		t.Fatal(err)
	}
	reports, err := check.CIAFiles(dir, src, []string{record.CIALatestPath, dayFile}, check.CIAOptions{})
	if err != nil || len(reports) != 2 {
		t.Fatalf("%d reports, %v", len(reports), err)
	}
	for _, r := range reports {
		if r.Worst() != check.OK {
			t.Errorf("%s: %v", r.Subject, r.Results)
		}
	}
	// A named file that is not part of the CIA record, or does not exist, fails
	// instead of being skipped.
	reports, err = check.CIAFiles(dir, src, []string{"data/v1/latest.json", "data/v1/cia/runs/2026/10/01/1105Z.jsno"}, check.CIAOptions{})
	if err != nil || len(reports) != 2 || !reports[0].Failed() || !reports[1].Failed() {
		t.Errorf("files outside the record: %v %v", reports, err)
	}
}

// Read over HTTP (raw GitHub, a bucket), a record the checks need but the
// server does not have is a failure that names the file and the server, never
// a pass and never a panic.
func TestRemoteModeMissingFiles(t *testing.T) {
	_, dir := generateExamples(t)
	const (
		hour5     = "data/v1/timestamps/2026/10/01/05Z.json"
		hour4     = "data/v1/timestamps/2026/10/01/04Z.json"
		witnessed = "data/v1/audit/witness/2026/10/01/052004Z.json"
	)
	var w record.Witness
	data, err := os.ReadFile(filepath.Join(dir, witnessed))
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Decode(data, "witness/v1", &w); err != nil || w.Previous == nil {
		t.Fatalf("%v", err)
	}
	for _, missing := range []string{hour4, w.Previous.Record, hourRunRecord(t, dir, hour5)} {
		if err := os.Remove(filepath.Join(dir, missing)); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()
	src, err := record.Open(context.Background(), srv.Client(), srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	keys := check.NewKeyring(src, "keys/")
	const hint = "not found at " + "http://" // the server's address follows
	_, r := check.Timestamp(src, hour5, check.TimestampOptions{})
	text := resultsOf(r)
	for _, name := range []string{"chain", "subject cia"} {
		if !strings.Contains(text, "FAIL "+name) {
			t.Errorf("%s is not reported as a failure:\n%s", name, text)
		}
	}
	if !strings.Contains(text, hint) || !strings.Contains(text, "(HTTP 404)") {
		t.Errorf("the missing file is not named:\n%s", text)
	}
	_, r = check.Witness(src, keys, witnessed)
	if text = resultsOf(r); !strings.Contains(text, "FAIL previous") || !strings.Contains(text, hint) {
		t.Errorf("witness record whose previous record is gone:\n%s", text)
	}
	r = check.Release(src, "data/v1/cia/releases/vault/"+strings.Repeat("0", 64), check.ReleaseOptions{})
	if text = resultsOf(r); !r.Failed() || !strings.Contains(text, hint) {
		t.Errorf("release that the server does not have:\n%s", text)
	}
}

func hourRunRecord(t *testing.T, dir, hour string) string {
	t.Helper()
	var ts record.Timestamp
	data, err := os.ReadFile(filepath.Join(dir, hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Decode(data, "timestamp/v1", &ts); err != nil || ts.Subject.CIA == nil {
		t.Fatalf("%v", err)
	}
	return ts.Subject.CIA.Record
}

func resultsOf(r *check.Report) string {
	var b strings.Builder
	r.Print(&b, false)
	return b.String()
}

// The percentiles in the day files are the nearest-rank percentiles of the
// latencies in the run records, computed here a second way, with floating
// point and the definition's own words.
func TestDayLatencyMatchesTheRunRecords(t *testing.T) {
	_, dir := generateExamples(t)
	var day record.CIADay
	data, err := os.ReadFile(filepath.Join(dir, dayFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Decode(data, "cia-day/v1", &day); err != nil {
		t.Fatal(err)
	}
	latencies := map[string][]int{}
	for i := 0; i < 288; i++ {
		slot := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * 5 * time.Minute)
		var run record.CIARun
		data, err := os.ReadFile(filepath.Join(dir, record.CIARunPath(slot)))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || record.Decode(data, "cia-run/v1", &run) != nil {
			t.Fatal(err)
		}
		for id, svc := range run.Services {
			if h := svc.Availability.Checks[0].Healthz; h != nil && h.LatencyMs != nil {
				latencies[id] = append(latencies[id], *h.LatencyMs)
			}
		}
	}
	for id, letters := range day.Services {
		values := latencies[id]
		sort.Ints(values)
		l := letters.Latency
		if l.Samples != len(values) {
			t.Errorf("%s: %d samples, %d latencies in the run records", id, l.Samples, len(values))
			continue
		}
		for p, got := range map[float64]*int{50: l.P50Ms, 95: l.P95Ms} {
			want := values[int(math.Ceil(p*float64(len(values))/100))-1]
			if *got != want {
				t.Errorf("%s p%.0f = %d, want %d", id, p, *got, want)
			}
		}
	}
	// The vault timed out four times that day and the run of 09:00 measured nothing: those runs have no latency.
	if n := day.Services["vault"].Latency.Samples; n != 169-4-1 {
		t.Errorf("vault samples %d, want %d", n, 169-4-1)
	}
}
