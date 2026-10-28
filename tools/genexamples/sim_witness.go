package main

import (
	"fmt"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/cosig"
	"github.com/diagnos-tech/audit/tools/internal/merkle"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// witness checks one log and cosigns it if it grew; it reports what the run
// did with the log.
func (s *sim) witness(l *logSim, at time.Time) (logOutcome, error) {
	if l.halted {
		return l.outcome("halted"), nil
	}
	if !l.equivocateAt.IsZero() && !at.Before(l.equivocateAt) && l.last != nil {
		err := s.equivocate(l, at)
		return l.outcome("finding"), err
	}
	size := l.tree.Size()
	if l.last != nil && size == l.last.rec.Checkpoint.Size {
		return l.outcome("unchanged"), nil
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
	cosigned, err := note.Sign(n, cosig.NewSigner(s.witnessV.Name(), s.witnessKey, func() time.Time { return at }))
	if err != nil {
		return logOutcome{}, err
	}

	rec := record.Witness{
		Schema: "witness/v1", Log: l.name, Origin: l.origin, URL: l.url,
		WitnessedAt: record.FormatTime(at),
		Checkpoint:  record.Checkpoint{Size: size, Root: b64(root[:]), Note: string(cosigned)},
		Cosignature: record.Cosignature{Name: s.witnessV.Name(), KeyHash: fmt.Sprintf("%08x", s.witnessV.KeyHash())},
		Consistency: []string{},
	}
	if l.last != nil {
		prev := l.last.rec.Checkpoint
		rec.Previous = &record.Previous{Size: prev.Size, Root: prev.Root, Record: l.last.path}
		proof, err := merkle.ConsistencyProof(prev.Size, size, &l.tree)
		if err != nil {
			return logOutcome{}, err
		}
		for _, h := range proof {
			rec.Consistency = append(rec.Consistency, b64(h[:]))
		}
	}
	path := record.WitnessPath(l.name, at)
	data, err := s.w.json(path, rec)
	if err != nil {
		return logOutcome{}, err
	}
	l.last = &witnessed{rec: rec, path: path, sha: sum(data)}

	ix := s.index(at)
	var prevSize *uint64
	if rec.Previous != nil {
		prevSize = &rec.Previous.Size
	}
	ix.Logs[l.name] = append(ix.Logs[l.name], record.IndexEntry{At: rec.WitnessedAt, Size: size, Prev: prevSize, Root: rec.Checkpoint.Root, Record: path})
	return l.outcome("witnessed"), nil
}

// outcome describes the log's last cosigned tree head, with the finding that
// halted it when there is one.
func (l *logSim) outcome(status string) logOutcome {
	out := logOutcome{status: status}
	if l.last != nil {
		out.size, out.record = l.last.rec.Checkpoint.Size, l.last.path
	}
	if status == "finding" || status == "halted" {
		out.finding = l.findingPath
	}
	return out
}

// equivocate makes the log present a second root for the size the witness
// already cosigned, which the witness records as a finding and then stops.
func (s *sim) equivocate(l *logSim, at time.Time) error {
	last := l.last.rec.Checkpoint
	fork := &merkle.Tree{}
	for i := range last.Size - 1 {
		h, _ := l.tree.Node(0, i)
		fork.AppendHash(h)
	}
	fork.AppendLeaf([]byte("a different last entry"))
	root, _ := merkle.Root(last.Size, fork)
	observed, err := s.checkpoint(l, last.Size, root)
	if err != nil {
		return err
	}
	f := record.Finding{
		Schema: "finding/v1", Log: l.name, Origin: l.origin, DetectedAt: record.FormatTime(at), Kind: "equivocation",
		Summary:     fmt.Sprintf("The log signed two different roots for size %d.", last.Size),
		Witnessed:   record.Evidence{Size: last.Size, Root: last.Root, Note: last.Note, Record: l.last.path},
		Observed:    record.Evidence{Size: last.Size, Root: b64(root[:]), Note: string(observed)},
		Consistency: []string{},
	}
	path := record.FindingPath(l.name, at)
	if _, err := s.w.json(path, f); err != nil {
		return err
	}
	l.findingPath = path
	summary := record.FindingSummary{Log: f.Log, Kind: f.Kind, DetectedAt: f.DetectedAt, Record: path, Summary: f.Summary}
	s.findings = append(s.findings, summary)
	ix := s.index(at)
	ix.Findings = append(ix.Findings, summary)
	l.halted = true
	return nil
}

func (s *sim) checkpoint(l *logSim, size uint64, root merkle.Hash) ([]byte, error) {
	body := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, b64(root[:]))
	return note.Sign(&note.Note{Text: body}, l.signer)
}
