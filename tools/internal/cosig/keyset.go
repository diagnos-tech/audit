package cosig

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

// versionSuffix is the "/v2" at the end of a key name. A witness that rotates
// its key publishes the new one under the next version of the same name.
var versionSuffix = regexp.MustCompile(`/v[0-9]+$`)

// Family is a key name without its version suffix: witness.example/latam/v2
// and witness.example/latam/v1 are keys of the family witness.example/latam. A
// name without a suffix is its own family.
func Family(name string) string { return versionSuffix.ReplaceAllString(name, "") }

// KeySet is the keys of one witness as keys/witness/<id>.vkey publishes them:
// the current key and, after a rotation, the keys it replaced. A signature is
// matched to a key by name and key hash, as signed-note does, so a record
// written under a previous key keeps verifying for as long as that key stays
// in the file.
type KeySet struct {
	keys []*Verifier
}

// ParseKeys reads a witness key file: one or more vkeys, one per line, the
// current key first and the previous keys after it. Blank lines are ignored,
// and so is the space around a key; nothing else is (no comments). Every key
// must belong to the witness of the first one, which means that the names
// differ at most in the version suffix, and no key may be listed twice (the
// same name and key hash), because a signature could not then be matched to
// one key. A file with a single key reads as it always did.
func ParseKeys(text string) (*KeySet, error) {
	type entry struct {
		line int
		text string
	}
	var entries []entry
	for i, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			entries = append(entries, entry{i + 1, l})
		}
	}
	if len(entries) == 0 {
		return nil, errors.New("cosig: the key file has no key; it needs one vkey per line")
	}
	// Name the line only when there is more than one to choose from: a file
	// with a single key keeps the error it has always had.
	where := func(e entry) string {
		if len(entries) == 1 {
			return ""
		}
		return fmt.Sprintf("line %d: ", e.line)
	}

	set := &KeySet{}
	lines := map[nameHash]int{}
	for _, e := range entries {
		v, err := NewVerifier(e.text)
		if err != nil {
			return nil, fmt.Errorf("%s%w", where(e), err)
		}
		if len(set.keys) > 0 && Family(v.name) != set.Family() {
			return nil, fmt.Errorf("%skey %q is not a key of %s: the keys of a witness differ only in the version at the end of the name",
				where(e), v.name, set.Family())
		}
		k := nameHash{v.name, v.hash}
		if prev, dup := lines[k]; dup {
			return nil, fmt.Errorf("%skey %q (key hash %08x) is already listed on line %d", where(e), v.name, v.hash, prev)
		}
		lines[k] = e.line
		set.keys = append(set.keys, v)
	}
	return set, nil
}

type nameHash struct {
	name string
	hash uint32
}

// Keys returns the keys, the current one first.
func (s *KeySet) Keys() []*Verifier { return append([]*Verifier(nil), s.keys...) }

// Current returns the current key, the first of the file.
func (s *KeySet) Current() *Verifier { return s.keys[0] }

// Family returns the name the keys share, without the version.
func (s *KeySet) Family() string { return Family(s.keys[0].name) }

// Names returns the name of each key, the current one first.
func (s *KeySet) Names() []string {
	names := make([]string, len(s.keys))
	for i, k := range s.keys {
		names[i] = k.name
	}
	return names
}

// Verifiers returns the cosignature/v1 verifiers of all the keys, to open a
// signed note with.
func (s *KeySet) Verifiers() []note.Verifier {
	vs := make([]note.Verifier, len(s.keys))
	for i, k := range s.keys {
		vs[i] = k
	}
	return vs
}

// NoteVerifiers returns the plain signed-note verifiers (algorithm 0x01) of
// the same keys, for what a witness signs besides checkpoints (Verifier.NoteVerifier).
func (s *KeySet) NoteVerifiers() ([]note.Verifier, error) {
	vs := make([]note.Verifier, len(s.keys))
	for i, k := range s.keys {
		v, err := k.NoteVerifier()
		if err != nil {
			return nil, err
		}
		vs[i] = v
	}
	return vs, nil
}
