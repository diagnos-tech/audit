package main

import (
	"fmt"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/cosig"
	"github.com/diagnos-tech/audit/tools/internal/merkle"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// latamName is the name of the second witness's key.
const latamName = "witness.example/latam/v1"

// witness2 is the second witness at work on one log: it cosigns the tree the log
// shows it with its own key, and keeps its own chain of records in its own
// namespace, with a consistency proof from its own previous head. It does not
// know what the primary did, and nothing of the primary's state is shared: when
// the primary halted the log on a finding, this witness went on witnessing the
// tree it was shown.
func (s *sim) witness2(l *logSim, at time.Time) (logOutcome, error) {
	size := l.tree.Size()
	if l.last2 != nil && size == l.last2.rec.Checkpoint.Size {
		return outcomeOf(l.last2, "unchanged"), nil
	}
	root, err := merkle.Root(size, &l.tree)
	if err != nil {
		return logOutcome{}, err
	}
	signed, err := s.checkpoint(l, size, root)
	if err != nil {
		return logOutcome{}, err
	}
	n, err := note.Open(signed, note.VerifierList(l.verifier))
	if err != nil {
		return logOutcome{}, err
	}
	cosigned, err := note.Sign(n, cosig.NewSigner(s.latamV.Name(), s.latamKey, func() time.Time { return at }))
	if err != nil {
		return logOutcome{}, err
	}
	rec := record.Witness{
		Schema: "witness/v1", Log: l.name, Origin: l.origin, URL: l.url,
		WitnessedAt: record.FormatTime(at),
		Checkpoint:  record.Checkpoint{Size: size, Root: b64(root[:]), Note: string(cosigned)},
		Cosignature: record.Cosignature{Name: s.latamV.Name(), KeyHash: fmt.Sprintf("%08x", s.latamV.KeyHash())},
		Consistency: []string{},
	}
	if l.last2 != nil {
		prev := l.last2.rec.Checkpoint
		rec.Previous = &record.Previous{Size: prev.Size, Root: prev.Root, Record: l.last2.path}
		proof, err := merkle.ConsistencyProof(prev.Size, size, &l.tree)
		if err != nil {
			return logOutcome{}, err
		}
		for _, h := range proof {
			rec.Consistency = append(rec.Consistency, b64(h[:]))
		}
	}
	path := record.WitnessPathOf(record.WitnessLatam, l.name, at)
	data, err := s.w.json(path, rec)
	if err != nil {
		return logOutcome{}, err
	}
	l.last2 = &witnessed{rec: rec, path: path, sha: sum(data)}
	return outcomeOf(l.last2, "witnessed"), nil
}

// outcomeOf describes a witness's last cosigned tree head.
func outcomeOf(w *witnessed, status string) logOutcome {
	return logOutcome{status: status, size: w.rec.Checkpoint.Size, record: w.path, root: w.rec.Checkpoint.Root}
}

// witness2All runs the second witness over every log in the slot, if the
// scenario says it ran. A partial run (a cold start) is cut short before it
// gets to the logs.
func (s *sim) witness2All(slot time.Time, plan v2Plan) (map[string]logOutcome, error) {
	if !plan.ran() {
		return nil, nil
	}
	out := map[string]logOutcome{}
	at := slot.Add(time.Duration(4+jitter("latam cosign", slot, 4)) * time.Second)
	for _, l := range s.logs {
		if plan.answer == partial {
			out[l.name] = logOutcome{status: "error"}
			continue
		}
		o, err := s.witness2(l, at)
		if err != nil {
			return nil, fmt.Errorf("%s at %s: %w", l.name, at, err)
		}
		out[l.name] = o
	}
	return out, nil
}
