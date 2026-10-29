package check

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/cosig"
	"github.com/diagnos-tech/audit/tools/internal/merkle"
)

// head is the parsed body of a C2SP tlog-checkpoint.
type head struct {
	Origin string
	Size   uint64
	Root   merkle.Hash
}

// openNote verifies a signed note and requires a valid signature from every
// one of the given keys. Signatures by other keys (other witnesses) are
// allowed and ignored.
func openNote(text string, keys ...note.Verifier) (*note.Note, error) {
	return openNoteBy(text, keys, nil)
}

// openNoteBy is openNote with one more requirement: a valid signature by at
// least one of oneOf, the keys of a single witness, which are its current key
// and the keys it replaced. A signature is matched to a key by name and key
// hash, so a note signed by a previous key verifies as long as the key is
// listed, and a signature by a key that is not listed is not one.
func openNoteBy(text string, required, oneOf []note.Verifier) (*note.Note, error) {
	known := append(slices.Clone(required), oneOf...)
	n, err := note.Open([]byte(text), note.VerifierList(known...))
	if err != nil {
		return nil, err
	}
	for _, k := range required {
		if findSig(n, k) == nil {
			return nil, fmt.Errorf("no valid signature by %s", k.Name())
		}
	}
	if len(oneOf) > 0 && !slices.ContainsFunc(oneOf, func(k note.Verifier) bool { return findSig(n, k) != nil }) {
		return nil, fmt.Errorf("no valid signature by %s%s", keyNames(oneOf), unlistedSignatures(n, oneOf))
	}
	return n, nil
}

// keyNames names one key, or says "any of" several.
func keyNames(keys []note.Verifier) string {
	names := make([]string, len(keys))
	for i, k := range keys {
		names[i] = k.Name()
	}
	if len(names) == 1 {
		return names[0]
	}
	return "any of " + strings.Join(names, ", ")
}

// unlistedSignatures says which signatures the note carries by keys of the
// same witness that the key file does not list: the way a record fails when a
// key was removed from the file after a rotation.
func unlistedSignatures(n *note.Note, listed []note.Verifier) string {
	var found []string
	for _, s := range n.UnverifiedSigs {
		for _, k := range listed {
			if cosig.Family(s.Name) == cosig.Family(k.Name()) {
				found = append(found, fmt.Sprintf("%s (key hash %08x)", s.Name, s.Hash))
				break
			}
		}
	}
	if len(found) == 0 {
		return ""
	}
	return "; the note is signed by " + strings.Join(found, ", ") + ", which the key file does not list"
}

func findSig(n *note.Note, k note.Verifier) *note.Signature {
	for i, s := range n.Sigs {
		if s.Name == k.Name() && s.Hash == k.KeyHash() {
			return &n.Sigs[i]
		}
	}
	return nil
}

// parseCheckpoint reads origin, size and root hash from a checkpoint body
// (C2SP tlog-checkpoint); extension lines are allowed and not interpreted.
func parseCheckpoint(body string) (head, error) {
	lines := strings.SplitAfter(body, "\n")
	if len(lines) < 4 || lines[len(lines)-1] != "" {
		return head{}, errors.New("checkpoint body needs origin, size and root hash lines")
	}
	origin := strings.TrimSuffix(lines[0], "\n")
	sizeText := strings.TrimSuffix(lines[1], "\n")
	rootText := strings.TrimSuffix(lines[2], "\n")
	if origin == "" {
		return head{}, errors.New("checkpoint has an empty origin line")
	}
	size, err := strconv.ParseUint(sizeText, 10, 64)
	if err != nil || strconv.FormatUint(size, 10) != sizeText {
		return head{}, fmt.Errorf("checkpoint size %q is not a canonical decimal", sizeText)
	}
	root, err := decodeHash(rootText)
	if err != nil {
		return head{}, fmt.Errorf("checkpoint root: %w", err)
	}
	for _, ext := range lines[3 : len(lines)-1] {
		if ext == "\n" {
			return head{}, errors.New("checkpoint has an empty extension line")
		}
	}
	return head{Origin: origin, Size: size, Root: root}, nil
}

// decodeHash parses a base64 tree hash, accepting only the canonical form.
func decodeHash(s string) (merkle.Hash, error) {
	var h merkle.Hash
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != len(h) || base64.StdEncoding.EncodeToString(b) != s {
		return h, fmt.Errorf("%q is not a base64 SHA-256 hash", s)
	}
	copy(h[:], b)
	return h, nil
}

func decodeProof(nodes []string) ([]merkle.Hash, error) {
	proof := make([]merkle.Hash, len(nodes))
	for i, s := range nodes {
		h, err := decodeHash(s)
		if err != nil {
			return nil, fmt.Errorf("proof node %d: %w", i, err)
		}
		proof[i] = h
	}
	return proof, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// short abbreviates a base64 hash for messages.
func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:8] + "…"
}
