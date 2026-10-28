package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/jcs"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// timestamp writes the hourly record: the subject, its imprint and a token
// from the first provider that answers.
func (s *sim) timestamp(hour, at time.Time, run record.Link) error {
	subject := record.Subject{Hour: record.FormatTime(hour), CIA: &run, Logs: map[string]record.SubjectLog{}}
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
		nonce := new(big.Int).SetUint64(s.nonces[hour])
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
