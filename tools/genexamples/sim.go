package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/cosig"
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
	findingPath  string
	findingRoot  string // the root the log signed a second time for the size it equivocated on
	equivocateAt time.Time

	last2 *witnessed // the second witness's last cosigned tree head
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
	// nonces are drawn at the start of each hour, whether or not a run
	// happens then, so that a gap in the auditor's runs does not shift the
	// generator and change the growth of the logs after it.
	nonces map[time.Time]uint64
	cia    *ciaSim

	logs       []*logSim
	witnessV   *cosig.Verifier
	witnessKey ed25519.PrivateKey
	latamV     *cosig.Verifier
	latamKey   ed25519.PrivateKey

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

// run simulates one auditor run every five minutes from start to end: the
// witness on both logs, the CIA run record, and, in the first run of each hour
// that happens, the hourly timestamp that pins that run record.
func (s *sim) run(start, end time.Time) error {
	var stamped time.Time
	for slot := start; !slot.After(end); slot = slot.Add(record.SlotLength) {
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
		if slot.Minute() == 0 && s.tsaFails[slot] < len(s.tsas) {
			s.nonces[slot] = s.rng.Uint64()
		}
		if inGap(slot) {
			continue // the auditor did not run: nothing is written for this slot
		}
		// When the auditor's own network fails nothing can be witnessed or stamped:
		// the run records that and the next run catches up.
		plan := v2Plan{}
		if !slot.Before(v2Start) {
			plan = planAt(slot)
		}
		down := slot.Equal(vantageSlot) || plan.europeDown
		outcomes := map[string]logOutcome{}
		for _, l := range s.logs {
			if down {
				outcomes[l.name] = logOutcome{status: "error"}
				continue
			}
			out, err := s.witness(l, at)
			if err != nil {
				return fmt.Errorf("%s at %s: %w", l.name, at, err)
			}
			outcomes[l.name] = out
		}
		hour := slot.Truncate(time.Hour)
		stamp := !hour.Equal(stamped) && !down
		finished := at.Add(3 * time.Second)
		if stamp {
			finished = at.Add(14 * time.Second) // after the slowest provider could answer
		}
		started := slot.Add(time.Second)
		var run *record.CIARun
		if slot.Before(v2Start) {
			run = s.cia.buildRun(slot, started, finished, outcomes)
		} else {
			if plan.answer == partial {
				finished = slot.Add(44 * time.Second) // the primary waited for the slow answer
			}
			latam, err := s.witness2All(slot, plan)
			if err != nil {
				return err
			}
			v2, err := s.cia.buildRunV2(slot, started, finished, outcomes, latam, plan)
			if err != nil {
				return fmt.Errorf("run record %s: %w", slot, err)
			}
			run = v2.AsRun()
		}
		link, err := s.cia.record(run, slot)
		if err != nil {
			return fmt.Errorf("run record %s: %w", slot, err)
		}
		if stamp {
			if err := s.timestamp(hour, at.Add(2*time.Second), link); err != nil {
				return fmt.Errorf("timestamp %s: %w", hour, err)
			}
			stamped = hour
		}
		s.lastRun = finished
	}
	return nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
