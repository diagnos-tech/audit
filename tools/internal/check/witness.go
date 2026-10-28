package check

import (
	"fmt"
	"strings"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/cosig"
	"github.com/diagnos-tech/audit/tools/internal/merkle"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// Witness checks one witness record:
//
//   - the checkpoint note carries a valid signature by the log's key and a
//     valid cosignature/v1 by the witness's key;
//   - the size and root the record repeats are the ones the note states;
//   - the file name and witnessedAt are the time inside the cosignature;
//   - the consistency proof connects the previous record's tree head (read
//     from that file) to this one.
//
// The witness is the one whose namespace the path is in (record.WitnessOf). The
// key of a witness other than the primary one may not be published yet; until
// it is, its cosignature is not checked and the report says so, and everything
// else about the record still is.
//
// It returns the record (nil if unreadable) so callers can walk chains.
func Witness(src record.Source, keys *Keyring, path string) (*record.Witness, *Report) {
	r := &Report{Subject: path}
	wid, _, ok := record.WitnessOf(path)
	if !ok {
		r.fail("file name", "%s is not the path of a witness record", path)
		return nil, r
	}
	rec, h, ok := signedHead(src, keys, wid, path, r)
	if ok {
		checkPrevious(src, rec, h, wid, r)
	}
	return rec, r
}

// signedHead reads a witness record and checks everything about it except
// the link to the previous record: signatures, cosignature time, file name
// and the tree head it repeats.
func signedHead(src record.Source, keys *Keyring, wid, path string, r *Report) (*record.Witness, head, bool) {
	rec, ok := readWitness(src, wid, path, r)
	if !ok {
		return nil, head{}, false
	}

	logKey, err := keys.Log(rec.Log, rec.Origin)
	if err != nil {
		r.fail("log key", "%v", err)
		return rec, head{}, false
	}
	witKey, absent, err := keys.OptionalWitnessKey(wid, rec.Cosignature.Name)
	if err != nil {
		r.fail("witness key", "%v", err)
		return rec, head{}, false
	}
	var n *note.Note
	if absent {
		n, err = openNote(rec.Checkpoint.Note, logKey)
	} else {
		n, err = openNote(rec.Checkpoint.Note, logKey, witKey)
	}
	if err != nil {
		r.fail("signatures", "%v", err)
		return rec, head{}, false
	}
	r.pass("log signature", "%s (key %08x)", logKey.Name(), logKey.KeyHash())

	if !cosignatureOK(n, witKey, absent, rec, wid, r) {
		return rec, head{}, false
	}

	h, err := parseCheckpoint(n.Text)
	switch {
	case err != nil:
		r.fail("tree head", "%v", err)
		return rec, head{}, false
	case h.Origin != rec.Origin:
		r.fail("tree head", "note origin %q, record origin %q", h.Origin, rec.Origin)
		return rec, head{}, false
	case h.Size != rec.Checkpoint.Size || encode(h.Root) != rec.Checkpoint.Root:
		r.fail("tree head", "note says size %d root %s; record says size %d root %s",
			h.Size, encode(h.Root), rec.Checkpoint.Size, rec.Checkpoint.Root)
		return rec, head{}, false
	}
	r.pass("tree head", "size %d, root %s", h.Size, rec.Checkpoint.Root)
	return rec, h, true
}

// cosignatureOK checks the witness's cosignature line against the record: its
// time is witnessedAt and its key hash the one the record names. With the
// witness's key it has been verified already; without it (the key is not
// published yet) the line is read as it stands and the report says that its
// signature was not checked.
func cosignatureOK(n *note.Note, key *cosig.Verifier, absent bool, rec *record.Witness, wid string, r *Report) bool {
	var sig note.Signature
	var hash uint32
	if absent {
		found := false
		for _, s := range n.UnverifiedSigs {
			if s.Name == rec.Cosignature.Name {
				sig, found = s, true
			}
		}
		if !found {
			r.fail("cosignature", "the note carries no signature by %s", rec.Cosignature.Name)
			return false
		}
		hash = sig.Hash
	} else {
		sig, hash = *findSig(n, key), key.KeyHash()
	}
	signedAt, err := cosig.Time(sig)
	switch {
	case err != nil:
		r.fail("cosignature", "%v", err)
		return false
	case record.FormatTime(signedAt) != rec.WitnessedAt:
		r.fail("cosignature", "signed at %s, but witnessedAt says %s", record.FormatTime(signedAt), rec.WitnessedAt)
		return false
	case fmt.Sprintf("%08x", hash) != rec.Cosignature.KeyHash:
		r.fail("cosignature", "key hash is %08x, the record says %s", hash, rec.Cosignature.KeyHash)
		return false
	case absent:
		r.warn("cosignature", "%s at %s; its signature is not checked: %s is not published yet", rec.Cosignature.Name, rec.WitnessedAt, WitnessKeyFileOf(wid))
		return true
	}
	r.pass("cosignature", "%s at %s", key.Name(), rec.WitnessedAt)
	return true
}

func readWitness(src record.Source, wid, path string, r *Report) (*record.Witness, bool) {
	data, err := src.Read(path)
	if err != nil {
		r.fail("read", "%v", err)
		return nil, false
	}
	var rec record.Witness
	if err := record.Decode(data, "witness/v1", &rec); err != nil {
		r.fail("format", "%v", err)
		return nil, false
	}
	t, err := record.ParseTime(rec.WitnessedAt)
	if err != nil {
		r.fail("format", "witnessedAt: %v", err)
		return nil, false
	}
	if want := record.WitnessPathOf(wid, rec.Log, t); want != path {
		r.fail("file name", "a record of %s witnessed at %s belongs at %s", rec.Log, rec.WitnessedAt, want)
		return nil, false
	}
	if !strings.HasSuffix(rec.URL, "/") {
		r.fail("format", "url %q has no trailing slash", rec.URL)
		return nil, false
	}
	return &rec, true
}

// checkPrevious verifies the link to the previous record: its tree head is
// what this record says, and the consistency proof connects the two.
func checkPrevious(src record.Source, rec *record.Witness, h head, wid string, r *Report) {
	if rec.Previous == nil {
		if len(rec.Consistency) != 0 {
			r.fail("consistency", "first record (no previous) with a non-empty proof")
			return
		}
		r.pass("consistency", "first record of %s: accepted on first use, nothing to prove", rec.Log)
		return
	}
	prev := rec.Previous
	if !strings.HasPrefix(prev.Record, record.NamespaceDir(wid)+rec.Log+"/witness/") || prev.Record >= recordPathOf(wid, rec) {
		r.fail("previous", "%s is not an earlier record of %s", prev.Record, rec.Log)
		return
	}
	data, err := src.Read(prev.Record)
	if err != nil {
		r.fail("previous", "%v", err)
		return
	}
	var old record.Witness
	if err := record.Decode(data, "witness/v1", &old); err != nil {
		r.fail("previous", "%s: %v", prev.Record, err)
		return
	}
	if old.Origin != rec.Origin || old.Checkpoint.Size != prev.Size || old.Checkpoint.Root != prev.Root {
		r.fail("previous", "%s holds size %d root %s, not size %d root %s",
			prev.Record, old.Checkpoint.Size, old.Checkpoint.Root, prev.Size, prev.Root)
		return
	}
	if prev.Size >= h.Size {
		r.fail("previous", "the tree did not grow: %d → %d", prev.Size, h.Size)
		return
	}

	oldRoot, err1 := decodeHash(prev.Root)
	proof, err2 := decodeProof(rec.Consistency)
	if err1 != nil || err2 != nil {
		r.fail("consistency", "%v", firstErr(err1, err2))
		return
	}
	if err := merkle.VerifyConsistency(prev.Size, h.Size, oldRoot, h.Root, proof); err != nil {
		r.fail("consistency", "%d → %d: %v", prev.Size, h.Size, err)
		return
	}
	r.pass("consistency", "%d → %d (%d hashes) from %s", prev.Size, h.Size, len(proof), prev.Record)
}

func recordPath(rec *record.Witness) string { return recordPathOf(record.WitnessEurope, rec) }

func recordPathOf(wid string, rec *record.Witness) string {
	t, _ := record.ParseTime(rec.WitnessedAt)
	return record.WitnessPathOf(wid, rec.Log, t)
}

func encode(h merkle.Hash) string { return b64(h[:]) }

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
