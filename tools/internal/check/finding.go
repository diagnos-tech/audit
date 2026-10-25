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
	t, err := record.ParseTime(f.DetectedAt)
	if err != nil || record.FindingPath(f.Log, t) != path {
		r.fail("file name", "a finding of %s detected at %s belongs at %s", f.Log, f.DetectedAt, record.FindingPath(f.Log, t))
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
	witKey, err := keys.Witness(name)
	if err != nil {
		r.fail("witness key", "%v", err)
		return &f, r
	}
	witnessed, ok := evidenceHead(f.Witnessed, "witnessed", r, logKey, witKey)
	if !ok {
		return &f, r
	}
	observed, ok := evidenceHead(f.Observed, "observed", r, logKey)
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

func evidenceHead(e record.Evidence, name string, r *Report, keys ...note.Verifier) (head, bool) {
	n, err := openNote(e.Note, keys...)
	if err != nil {
		r.fail(name, "%v", err)
		return head{}, false
	}
	h, err := parseCheckpoint(n.Text)
	if err != nil || h.Size != e.Size || encode(h.Root) != e.Root {
		r.fail(name, "the note does not state size %d root %s (%v)", e.Size, e.Root, err)
		return head{}, false
	}
	r.pass(name, "size %d root %s, signed by %d required key(s)", e.Size, short(e.Root), len(keys))
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
