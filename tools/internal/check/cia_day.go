package check

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// validateDay checks what a day file says about itself: letters only where a
// run was recorded, and spans that match the letters beneath them. It needs no
// run record, so it also covers days whose records are not at hand.
func validateDay(d *record.CIADay) []string {
	var problems []string
	for _, id := range sortedKeys(d.Services) {
		for _, name := range record.Dimensions {
			for i, l := range []byte(d.Services[id].Dimension(name)) {
				if d.Runs[i] == '0' && l != '-' {
					problems = append(problems, fmt.Sprintf("%s %s has %q in slot %d, where no run was recorded", id, name, l, i))
				}
			}
		}
	}
	for _, id := range sortedKeys(d.Services) {
		if problem := latencyProblem(d.Services[id].Latency, d.Runs); problem != "" {
			problems = append(problems, id+" "+problem)
		}
	}
	covered := map[string][]bool{}
	var prev *record.CIASpan
	for k := range d.Spans {
		s := &d.Spans[k]
		letters, known := d.Services[s.Service]
		switch {
		case !known || !slices.Contains(record.Dimensions[:], s.Dimension):
			problems = append(problems, fmt.Sprintf("span %d names %s %s, which the day does not have", k, s.Service, s.Dimension))
			continue
		case s.From > s.To || s.To >= cia.SlotsPerDay || s.From < 0:
			problems = append(problems, fmt.Sprintf("span %d covers slots %d to %d", k, s.From, s.To))
			continue
		case prev != nil && spanOrder(*prev) >= spanOrder(*s):
			problems = append(problems, fmt.Sprintf("span %d is out of order", k))
		case prev != nil && prev.Service == s.Service && prev.Dimension == s.Dimension && prev.To >= s.From:
			problems = append(problems, fmt.Sprintf("span %d overlaps the span before it", k))
		}
		prev = s
		key := s.Service + "/" + s.Dimension
		if covered[key] == nil {
			covered[key] = make([]bool, cia.SlotsPerDay)
		}
		for i := s.From; i <= s.To; i++ {
			covered[key][i] = true
			if d.Runs[i] != '1' || letters.Dimension(s.Dimension)[i] != cia.Letter(s.Level) {
				problems = append(problems, fmt.Sprintf("span %d (%s %s, slots %d-%d): slot %d is not a %s slot with a run", k, s.Service, s.Dimension, s.From, s.To, i, s.Level))
				break
			}
		}
	}
	for _, id := range sortedKeys(d.Services) {
		for _, name := range record.Dimensions {
			for i, l := range []byte(d.Services[id].Dimension(name)) {
				if c := covered[id+"/"+name]; (l == 'w' || l == 'f') && (c == nil || !c[i]) {
					problems = append(problems, fmt.Sprintf("%s %s slot %d is %q but no span covers it", id, name, i, l))
				}
			}
		}
	}
	return problems
}

// latencyProblem checks the latency entry of a service on its own: present,
// with a latency for each of the 288 slots (nil where the slot has no run), and
// samples and percentiles that follow from those latencies.
func latencyProblem(l *record.CIALatency, runs string) string {
	if l == nil {
		return "has no latency: every day file carries the latency of each of its services"
	}
	if len(l.SlotsMs) != cia.SlotsPerDay {
		return fmt.Sprintf("latency.slotsMs has %d entries, a day has %d", len(l.SlotsMs), cia.SlotsPerDay)
	}
	for i, ms := range l.SlotsMs {
		if ms != nil && runs[i] != '1' {
			return fmt.Sprintf("latency.slotsMs has a latency in slot %d, where no run was recorded", i)
		}
	}
	if want := cia.DayLatency(l.SlotsMs); latencyValue(want) != latencyValue(l) {
		return fmt.Sprintf("latency %v does not follow from its slotsMs, which give %v", latencyValue(l), latencyValue(want))
	}
	return ""
}

func spanOrder(s record.CIASpan) string {
	return fmt.Sprintf("%s/%d/%03d", s.Service, cia.DimIndex(s.Dimension), s.From)
}

// compareDay lists how a day file differs from the one derived from the run
// records. Without complete, slots that have no run record in these files
// (the files are a slice of a longer history) are not compared.
func compareDay(want, got *record.CIADay, present [cia.SlotsPerDay]bool, complete bool) []string {
	if complete {
		return diffEncoded(want, got, func(d *record.CIADay) { d.UpdatedAt = "" })
	}
	var diffs []string
	for i, p := range present {
		if p && got.Runs[i] != '1' {
			diffs = append(diffs, fmt.Sprintf("slot %d has a run record but the day file says no run", i))
		}
	}
	for _, id := range sortedKeys(want.Services) {
		w, g := want.Services[id].Latency, got.Services[id].Latency
		for i, p := range present {
			if p && g != nil && len(g.SlotsMs) == cia.SlotsPerDay && !equalMs(w.SlotsMs[i], g.SlotsMs[i]) {
				diffs = append(diffs, fmt.Sprintf("%s latency in slot %d is %s, the run records give %s", id, i, msText(g.SlotsMs[i]), msText(w.SlotsMs[i])))
				break
			}
		}
	}
	for _, id := range sortedKeys(mergeKeys(want.Services, got.Services)) {
		for _, name := range record.Dimensions {
			w, g := want.Services[id].Dimension(name), got.Services[id].Dimension(name)
			if w == "" {
				w = strings.Repeat("-", cia.SlotsPerDay)
			}
			if g == "" {
				g = strings.Repeat("-", cia.SlotsPerDay)
			}
			for i, p := range present {
				if p && w[i] != g[i] {
					diffs = append(diffs, fmt.Sprintf("%s %s slot %d is %q, the run records give %q", id, name, i, g[i], w[i]))
					break
				}
			}
		}
	}
	wantSpans, gotSpans := want.Spans, clipSpans(got.Spans, present)
	if len(wantSpans) != len(gotSpans) {
		diffs = append(diffs, fmt.Sprintf("%d spans, the run records give %d", len(gotSpans), len(wantSpans)))
	} else {
		for k := range wantSpans {
			if fmt.Sprint(wantSpans[k]) != fmt.Sprint(gotSpans[k]) {
				diffs = append(diffs, fmt.Sprintf("span %d is %v, the run records give %v", k, gotSpans[k], wantSpans[k]))
			}
		}
	}
	return diffs
}

// latencyValue makes the summary of a latency entry comparable.
func latencyValue(l *record.CIALatency) string {
	if l == nil {
		return "none"
	}
	p50, p95 := msText(l.P50Ms), msText(l.P95Ms)
	return fmt.Sprintf("p50 %s p95 %s samples %d", p50, p95, l.Samples)
}

func equalMs(a, b *int) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }

func msText(p *int) string {
	if p == nil {
		return "null"
	}
	return fmt.Sprint(*p)
}

// clipSpans cuts spans at the slots that have no run record.
func clipSpans(spans []record.CIASpan, present [cia.SlotsPerDay]bool) []record.CIASpan {
	var out []record.CIASpan
	for _, s := range spans {
		for i := s.From; i <= s.To && i < cia.SlotsPerDay; {
			if !present[i] {
				i++
				continue
			}
			j := i
			for j+1 <= s.To && j+1 < cia.SlotsPerDay && present[j+1] {
				j++
			}
			c := s
			c.From, c.To = i, j
			out = append(out, c)
			i = j + 1
		}
	}
	return out
}

func mergeKeys[V any](a, b map[string]V) map[string]V {
	out := map[string]V{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// diffEncoded compares the canonical encodings of two values (after prepare
// has blanked what is not part of the derivation) and describes the first
// line that differs.
func diffEncoded[T any](want, got *T, prepare func(*T)) []string {
	w, g := *want, *got
	prepare(&w)
	prepare(&g)
	wb, err1 := record.Encode(w)
	gb, err2 := record.Encode(g)
	if err1 != nil || err2 != nil {
		return []string{fmt.Sprintf("cannot encode: %v %v", err1, err2)}
	}
	if bytes.Equal(wb, gb) {
		return nil
	}
	wl, gl := strings.Split(string(wb), "\n"), strings.Split(string(gb), "\n")
	for i := 0; i < min(len(wl), len(gl)); i++ {
		if wl[i] != gl[i] {
			return []string{fmt.Sprintf("line %d is %q, derived from the facts it is %q", i+1, strings.TrimSpace(gl[i]), strings.TrimSpace(wl[i]))}
		}
	}
	return []string{fmt.Sprintf("%d lines, derived from the facts %d", len(gl), len(wl))}
}

func dayStart(day string) (time.Time, error) { return time.Parse(record.DayLayout, day) }
