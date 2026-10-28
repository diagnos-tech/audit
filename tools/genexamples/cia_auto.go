package main

import (
	"fmt"
	"slices"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/cia"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// autoEvents plays the auditor's policy for the incidents it opens on its own
// (INCIDENTS-CONTRACT §5) over the history, oldest first, and returns the
// events it would have written:
//
//   - availability: a service failing in three consecutive recorded slots opens
//     a high incident that started in the first of them; two consecutive
//     slots that are not failing resolve it, so it covers the failed slots;
//   - integrity: the first failing slot opens an incident at once (critical for
//     a served-bytes mismatch or a witness finding); a finding or a halt never
//     resolves it, anything else resolves after two slots that are not failing;
//   - a slot that measured nothing neither counts nor interrupts.
func autoEvents(history []cia.Slot) []record.CIAIncidentEvent {
	var out []record.CIAIncidentEvent
	services := cia.Services(slotPointers(history)...)
	for _, service := range services {
		for _, category := range []string{"A", "I"} {
			t := &tracker{service: service, category: category}
			for _, slot := range history {
				if dims, ok := slot.Services[service]; ok {
					out = append(out, t.step(slot.Time, dims[map[string]int{"A": 0, "I": 1}[category]])...)
				}
			}
		}
	}
	return out
}

func slotPointers(history []cia.Slot) []*cia.Slot {
	out := make([]*cia.Slot, len(history))
	for i := range history {
		out[i] = &history[i]
	}
	return out
}

type tracker struct {
	service, category string
	fails             []time.Time // consecutive failing slots since the last one that was not
	codes             []string
	oks               []time.Time // slots that were not failing since the last failing one
	open              *openIncident
}

type openIncident struct {
	id       string
	seq      int
	started  time.Time
	severity string
	reasons  []string
}

// sticky incidents are never resolved by good measurements: a log that
// contradicted itself stays a fact.
func (o *openIncident) sticky() bool {
	return slices.Contains(o.reasons, "finding") || slices.Contains(o.reasons, "halted")
}

func (t *tracker) step(at time.Time, res cia.Result) []record.CIAIncidentEvent {
	switch {
	case res.Level == record.LevelNone:
		return nil
	case res.Level == record.LevelFail && t.open == nil:
		t.fails, t.codes = append(t.fails, at), append(t.codes, res.Code)
		need := map[string]int{"A": 3, "I": 1}[t.category]
		if len(t.fails) < need {
			return nil
		}
		t.open = &openIncident{started: t.fails[0], seq: 1, reasons: unique(t.codes)}
		t.open.id = fmt.Sprintf("%s-auto-%s-%s-%s", t.open.started.Format("2006-01-02"), t.service,
			map[string]string{"A": "a", "I": "i"}[t.category], t.open.started.Format("1504"))
		t.open.severity = t.severity()
		t.fails, t.codes = nil, nil
		return []record.CIAIncidentEvent{t.event("opened", at, nil)}
	case res.Level == record.LevelFail:
		t.oks = nil
		old, oldSeverity := len(t.open.reasons), t.open.severity
		t.open.reasons = unique(append(t.open.reasons, res.Code))
		t.open.severity = t.severity()
		if len(t.open.reasons) == old && t.open.severity == oldSeverity {
			return nil
		}
		t.open.seq++
		return []record.CIAIncidentEvent{t.event("updated", at, nil)}
	}
	t.fails, t.codes = nil, nil
	if t.open == nil || t.open.sticky() {
		return nil
	}
	if t.oks = append(t.oks, at); len(t.oks) < 2 {
		return nil
	}
	t.open.seq++
	e := t.event("resolved", at, &t.oks[0])
	t.open, t.oks = nil, nil
	return []record.CIAIncidentEvent{e}
}

// severity: high for a failing service or an invalid release, critical when
// bytes differ from what was signed or a log contradicted itself.
func (t *tracker) severity() string {
	if t.category == "I" {
		for _, r := range t.open.reasons {
			if r == "served-mismatch" || r == "finding" || r == "halted" {
				return "critical"
			}
		}
	}
	return "high"
}

func (t *tracker) event(typ string, at time.Time, resolvedAt *time.Time) record.CIAIncidentEvent {
	o := t.open
	e := record.CIAIncidentEvent{
		Schema: "cia-incident-event/v1", ID: o.id, Seq: o.seq, Type: typ, At: record.FormatTime(at), Source: "auditor",
		Categories: []string{t.category}, Services: []string{t.service}, Severity: o.severity,
		StartedAt: record.FormatTime(o.started), Reasons: slices.Clone(o.reasons), Run: record.CIARunPath(at),
	}
	if resolvedAt != nil {
		e.ResolvedAt = ptr(record.FormatTime(*resolvedAt))
	}
	return e
}

func unique(list []string) []string {
	var out []string
	for _, s := range list {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
