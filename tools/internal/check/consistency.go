package check

import (
	"context"
	"fmt"
	"net/http"

	"github.com/diagnos-tech/audit/tools/internal/merkle"
	"github.com/diagnos-tech/audit/tools/internal/record"
	"github.com/diagnos-tech/audit/tools/internal/tiles"
)

// FromLog checks witness records against the log itself instead of against
// the proof the witness recorded: it fetches the log's current checkpoint,
// verifies the log's signature on it, rebuilds consistency proofs from the
// log's hash tiles and verifies them.
//
// With newPath empty it proves that the log today extends oldPath's tree.
// Otherwise it proves oldPath → newPath, and newPath → today when the log
// has grown since.
func FromLog(ctx context.Context, client *http.Client, src record.Source, keys *Keyring, oldPath, newPath, logURL string) *Report {
	r := &Report{Subject: oldPath}
	if newPath != "" {
		r.Subject += " → " + newPath
	}
	label := ""
	if newPath != "" {
		label = "old "
	}
	old, oldHead, ok := labelled(r, label, func(sub *Report) (*record.Witness, head, bool) {
		return signedHead(src, keys, oldPath, sub)
	})
	if !ok {
		return r
	}
	target, targetHead := old, oldHead
	if newPath != "" {
		if target, targetHead, ok = labelled(r, "new ", func(sub *Report) (*record.Witness, head, bool) {
			return signedHead(src, keys, newPath, sub)
		}); !ok {
			return r
		}
		if target.Log != old.Log {
			r.fail("logs", "%s is a record of %s, %s of %s", oldPath, old.Log, newPath, target.Log)
			return r
		}
		if targetHead.Size < oldHead.Size {
			r.fail("order", "the newer record has the smaller tree (%d < %d)", targetHead.Size, oldHead.Size)
			return r
		}
	}

	if logURL == "" {
		logURL = old.URL
	}
	cur, reader, ok := currentCheckpoint(ctx, client, keys, old, logURL, r)
	if !ok {
		return r
	}
	if cur.Size < targetHead.Size {
		r.fail("rollback", "the log is at size %d, smaller than the witnessed %d", cur.Size, targetHead.Size)
		return r
	}

	if newPath != "" {
		proveFromTiles(reader, oldHead, targetHead, r)
	}
	if newPath == "" || targetHead.Size < cur.Size {
		proveFromTiles(reader, targetHead, cur, r)
	}
	r.pass("tiles", "%d tile requests to %s", reader.Fetches, logURL)
	return r
}

// labelled runs a check into a scratch report and copies its results into r
// with their names prefixed, to tell the old record's checks from the new.
func labelled(r *Report, prefix string, f func(*Report) (*record.Witness, head, bool)) (*record.Witness, head, bool) {
	sub := &Report{}
	w, h, ok := f(sub)
	for _, res := range sub.Results {
		res.Name = prefix + res.Name
		r.Results = append(r.Results, res)
	}
	return w, h, ok
}

// currentCheckpoint fetches and verifies the log's checkpoint, and returns a
// tile reader for the tree it describes.
func currentCheckpoint(ctx context.Context, client *http.Client, keys *Keyring, rec *record.Witness, logURL string, r *Report) (head, *tiles.Reader, bool) {
	logKey, err := keys.Log(rec.Log, rec.Origin)
	if err != nil {
		r.fail("log key", "%v", err)
		return head{}, nil, false
	}
	reader, err := tiles.NewReader(ctx, client, logURL, 0)
	if err != nil {
		r.fail("log", "%v", err)
		return head{}, nil, false
	}
	text, err := reader.Checkpoint()
	if err != nil {
		r.fail("log checkpoint", "%v", err)
		return head{}, nil, false
	}
	n, err := openNote(string(text), logKey)
	if err != nil {
		r.fail("log checkpoint", "%v", err)
		return head{}, nil, false
	}
	cur, err := parseCheckpoint(n.Text)
	if err != nil || cur.Origin != rec.Origin {
		r.fail("log checkpoint", "%v (origin %q)", err, cur.Origin)
		return head{}, nil, false
	}
	r.pass("log checkpoint", "%s now at size %d, root %s, signed by the log", logURL, cur.Size, short(encode(cur.Root)))
	reader, _ = tiles.NewReader(ctx, client, logURL, cur.Size)
	return cur, reader, true
}

func proveFromTiles(reader *tiles.Reader, from, to head, r *Report) {
	name := fmt.Sprintf("%d → %d", from.Size, to.Size)
	proof, err := merkle.ConsistencyProof(from.Size, to.Size, reader)
	if err != nil {
		r.fail(name, "building the proof from tiles: %v", err)
		return
	}
	if err := merkle.VerifyConsistency(from.Size, to.Size, from.Root, to.Root, proof); err != nil {
		r.fail(name, "%v", err)
		return
	}
	r.pass(name, "consistent: proof of %d hashes rebuilt from the log's tiles", len(proof))
}
