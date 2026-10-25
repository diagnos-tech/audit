package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand/v2"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/cosig"
	"github.com/diagnos-tech/audit/tools/internal/jcs"
	"github.com/diagnos-tech/audit/tools/internal/merkle"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// logSim is one transparency log and what the witness knows about it.
type logSim struct {
	name, origin, url string
	tree              merkle.Tree
	signer            note.Signer
	verifier          note.Verifier
	vkey              string
	grow              func(t time.Time, r *rand.Rand) int

	last         *witnessed // last cosigned tree head
	halted       bool       // after a finding the witness stops cosigning
	equivocateAt time.Time
}

type witnessed struct {
	rec  record.Witness
	path string
	sha  string
}

// sim plays the witness over a span of time and writes what it would commit.
type sim struct {
	w   *writer
	rng *rand.Rand

	logs       []*logSim
	witnessV   *cosig.Verifier
	witnessKey ed25519.PrivateKey

	tsas     []*exampleTSA
	tsaFails map[time.Time]int // hour → how many providers fail before one answers
	lastHour *record.StateTimestamp
	latestTS *record.LatestTimestamp
	lastRun  time.Time
	findings []record.FindingSummary
	idx      map[string]*record.Index // month → index
}

func (s *sim) index(t time.Time) *record.Index {
	m := record.Month(t)
	if s.idx[m] == nil {
		s.idx[m] = &record.Index{Schema: "index/v1", Month: m, Logs: map[string][]record.IndexEntry{},
			Timestamps: []record.IndexTimestamp{}, Findings: []record.FindingSummary{}}
	}
	return s.idx[m]
}

// run simulates one witness run every five minutes from start to end.
func (s *sim) run(start, end time.Time) error {
	for slot := start; !slot.After(end); slot = slot.Add(5 * time.Minute) {
		for _, l := range s.logs {
			for range l.grow(slot, s.rng) {
				var leaf [32]byte
				for i := range leaf {
					leaf[i] = byte(s.rng.UintN(256))
				}
				l.tree.AppendLeaf(leaf[:])
			}
		}
		at := slot.Add(time.Duration(2+s.rng.IntN(6)) * time.Second)
		committed := false
		for _, l := range s.logs {
			did, err := s.witness(l, at)
			if err != nil {
				return fmt.Errorf("%s at %s: %w", l.name, at, err)
			}
			committed = committed || did
		}
		if slot.Minute() == 0 {
			if err := s.timestamp(slot, at.Add(2*time.Second)); err != nil {
				return fmt.Errorf("timestamp %s: %w", slot, err)
			}
			committed = true
		}
		if committed {
			s.lastRun = at.Add(3 * time.Second)
		}
	}
	return nil
}

// witness checks one log and cosigns it if it grew; it reports whether
// anything was written.
func (s *sim) witness(l *logSim, at time.Time) (bool, error) {
	if l.halted {
		return false, nil
	}
	if !l.equivocateAt.IsZero() && !at.Before(l.equivocateAt) && l.last != nil {
		return true, s.equivocate(l, at)
	}
	size := l.tree.Size()
	if l.last != nil && size == l.last.rec.Checkpoint.Size {
		return false, nil
	}
	root, err := merkle.Root(size, &l.tree)
	if err != nil {
		return false, err
	}
	signed, err := s.checkpoint(l, size, root)
	if err != nil {
		return false, err
	}
	n, err := note.Open(signed, note.VerifierList(l.verifier))
	if err != nil {
		return false, err
	}
	cosigned, err := note.Sign(n, cosig.NewSigner(s.witnessV.Name(), s.witnessKey, func() time.Time { return at }))
	if err != nil {
		return false, err
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
			return false, err
		}
		for _, h := range proof {
			rec.Consistency = append(rec.Consistency, b64(h[:]))
		}
	}
	path := record.WitnessPath(l.name, at)
	data, err := s.w.json(path, rec)
	if err != nil {
		return false, err
	}
	l.last = &witnessed{rec: rec, path: path, sha: sum(data)}

	ix := s.index(at)
	var prevSize *uint64
	if rec.Previous != nil {
		prevSize = &rec.Previous.Size
	}
	ix.Logs[l.name] = append(ix.Logs[l.name], record.IndexEntry{At: rec.WitnessedAt, Size: size, Prev: prevSize, Root: rec.Checkpoint.Root, Record: path})
	return true, nil
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

// timestamp writes the hourly record: the subject, its imprint and a token
// from the first provider that answers.
func (s *sim) timestamp(hour, at time.Time) error {
	subject := record.Subject{Hour: record.FormatTime(hour), Logs: map[string]record.SubjectLog{}}
	for _, l := range s.logs {
		if l.last != nil {
			c := l.last.rec.Checkpoint
			subject.Logs[l.name] = record.SubjectLog{Origin: l.origin, Size: c.Size, Root: c.Root, Record: l.last.path, SHA256: l.last.sha}
		}
	}
	if s.lastHour != nil {
		subject.Prev = &record.Link{Record: s.lastHour.Record, SHA256: s.lastHour.SHA256}
	}
	raw, err := json.Marshal(subject)
	if err != nil {
		return err
	}
	canonical, err := jcs.Canonicalize(raw)
	if err != nil {
		return err
	}
	imprint := sha256.Sum256(canonical)

	rec := record.Timestamp{
		Schema: "timestamp/v1", Hour: subject.Hour, SubjectRaw: raw,
		Imprint: hex.EncodeToString(imprint[:]), Attempts: []record.Attempt{},
	}
	failures := s.tsaFails[hour]
	errorsSeen := []string{"HTTP 503 Service Unavailable", "timeout after 10s"}
	for i, tsa := range s.tsas {
		if i < failures {
			rec.Attempts = append(rec.Attempts, record.Attempt{Provider: tsa.provider, Error: errorsSeen[i%len(errorsSeen)]})
			continue
		}
		genTime := at.Add(time.Duration(1+i*10) * time.Second)
		nonce := new(big.Int).SetUint64(s.rng.Uint64())
		der, serial, err := tsa.stamp(imprint[:], genTime, nonce)
		if err != nil {
			return err
		}
		file := record.TokenPath(hour)
		if err := s.w.raw(file, der); err != nil {
			return err
		}
		rec.Token = &record.Token{
			Provider: tsa.provider, URL: tsa.url, File: file, SHA256: sum(der),
			GenTime: record.FormatTime(genTime), Serial: hex.EncodeToString(serial.Bytes()), Policy: tsa.policy.String(),
			TSA: tsa.cert.Subject.String(), Checks: []string{"status", "imprint", "nonce", "time", "signature"},
		}
		break
	}

	path := record.TimestampPath(hour)
	data, err := s.w.json(path, rec)
	if err != nil {
		return err
	}
	s.lastHour = &record.StateTimestamp{Hour: rec.Hour, Record: path, SHA256: sum(data)}

	entry := record.IndexTimestamp{Hour: rec.Hour, Record: path, SHA256: sum(data), Imprint: rec.Imprint}
	s.latestTS = &record.LatestTimestamp{Hour: rec.Hour, Record: path, Imprint: rec.Imprint}
	if subject.Prev != nil {
		entry.Prev = &subject.Prev.SHA256
	}
	if t := rec.Token; t != nil {
		entry.Provider, entry.GenTime = &t.Provider, &t.GenTime
		s.latestTS.Token = &record.LatestToken{Provider: t.Provider, GenTime: t.GenTime, File: t.File}
	}
	ix := s.index(hour)
	ix.Timestamps = append(ix.Timestamps, entry)
	return nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
