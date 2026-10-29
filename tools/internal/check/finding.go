package check

import (
	"errors"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/merkle"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// Finding checks that a finding is evidence and not an opinion: the observed
// checkpoint is signed by the log, the witnessed one by the log and the
// witness, and the two conflict the way the kind says.
func Finding(src record.Source, keys *Keyring, path string) (*record.Finding, *Report) {
	r := &Report{Subject: path}
	data, err := src.Read(path)
	if err != nil {
		r.fail("read", "%v", err)
		return nil, r
	}
	var f record.Finding
	if err := record.Decode(data, "finding/v1", &f); err != nil {
		r.fail("format", "%v", err)
		return nil, r
	}
	wid := witnessOf(path)
	t, err := record.ParseTime(f.DetectedAt)
	if err != nil || record.FindingPathOf(wid, f.Log, t) != path {
		r.fail("file name", "a finding of %s detected at %s belongs at %s", f.Log, f.DetectedAt, record.FindingPathOf(wid, f.Log, t))
		return nil, r
	}
	if other, _, ok := record.WitnessOf(f.Witnessed.Record); !ok || other != wid {
		r.fail("witnessed", "%s is not a record of the witness whose finding this is (%s)", f.Witnessed.Record, wid)
		return nil, r
	}

	logKey, err := keys.Log(f.Log, f.Origin)
	if err != nil {
		r.fail("log key", "%v", err)
		return &f, r
	}
	name, err := witnessName(src, f.Witnessed.Record)
	if err != nil {
		r.fail("witnessed", "%v", err)
		return &f, r
	}
	witKeys, absent, err := keys.OptionalWitnessKeys(wid, name)
	if err != nil {
		r.fail("witness key", "%v", err)
		return &f, r
	}
	// The log must have signed the witnessed checkpoint, and so must one of the
	// witness's keys: its current one, or one it replaced.
	var cosigners []note.Verifier
	if absent {
		r.warn("witness key", "%s is not published yet: the cosignature on the witnessed checkpoint is not checked", WitnessKeyFileOf(wid))
	} else {
		cosigners = witKeys.Verifiers()
	}
	witnessed, ok := evidenceHead(f.Witnessed, "witnessed", r, []note.Verifier{logKey}, cosigners)
	if !ok {
		return &f, r
	}
	observed, ok := evidenceHead(f.Observed, "observed", r, []note.Verifier{logKey}, nil)
	if !ok {
		return &f, r
	}
	if witnessed.Origin != f.Origin || observed.Origin != f.Origin {
		r.fail("origin", "the checkpoints are for %q and %q, not %q", witnessed.Origin, observed.Origin, f.Origin)
		return &f, r
	}

	switch f.Kind {
	case "equivocation":
		if observed.Size == witnessed.Size && observed.Root != witnessed.Root {
			r.pass("evidence", "two roots signed by the log for size %d", observed.Size)
			return &f, r
		}
	case "rollback":
		if observed.Size < witnessed.Size {
			r.pass("evidence", "the log signed size %d after the witness cosigned %d", observed.Size, witnessed.Size)
			return &f, r
		}
	case "inconsistent":
		proof, err := decodeProof(f.Consistency)
		if err == nil && observed.Size > witnessed.Size {
			err = merkle.VerifyConsistency(witnessed.Size, observed.Size, witnessed.Root, observed.Root, proof)
			if errors.Is(err, merkle.ErrInconsistent) {
				r.pass("evidence", "the log's proof %d → %d does not verify: %v", witnessed.Size, observed.Size, err)
				return &f, r
			}
		}
	}
	r.fail("evidence", "the checkpoints do not show a %s", f.Kind)
	return &f, r
}

func evidenceHead(e record.Evidence, name string, r *Report, required, oneOf []note.Verifier) (head, bool) {
	n, err := openNoteBy(e.Note, required, oneOf)
	if err != nil {
		r.fail(name, "%v", err)
		return head{}, false
	}
	h, err := parseCheckpoint(n.Text)
	if err != nil || h.Size != e.Size || encode(h.Root) != e.Root {
		r.fail(name, "the note does not state size %d root %s (%v)", e.Size, e.Root, err)
		return head{}, false
	}
	signers := len(required)
	if len(oneOf) > 0 {
		signers++
	}
	r.pass(name, "size %d root %s, signed by %d required key(s)", e.Size, short(e.Root), signers)
	return h, true
}

// witnessName reads the cosignature name from the witnessed record, so the
// keyring can insist the key it loads is the one that cosigned.
func witnessName(src record.Source, path string) (string, error) {
	data, err := src.Read(path)
	if err != nil {
		return "", err
	}
	var w record.Witness
	if err := record.Decode(data, "witness/v1", &w); err != nil {
		return "", err
	}
	return w.Cosignature.Name, nil
}
