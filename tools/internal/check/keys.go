package check

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/cosig"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// WitnessKeyFile is the primary witness's key file under the keys directory.
const WitnessKeyFile = "witness/auditor.vkey"

// WitnessKeyFileOf is the key file of the named witness: the primary witness
// (europe) keeps the name its key was published under, the others are
// witness/<id>.vkey.
func WitnessKeyFileOf(witness string) string {
	if witness == record.WitnessEurope {
		return WitnessKeyFile
	}
	return "witness/" + witness + ".vkey"
}

// Keyring loads verifier keys on demand from a keys directory laid out like
// keys/ in the repository: logs/<log>.vkey, witness/auditor.vkey and
// witness/<id>.vkey for every other witness. A witness file holds the
// witness's current key and, after a rotation, the keys it replaced, one per
// line (cosig.ParseKeys).
//
// Keys read from the repository under check only prove that the repository
// is consistent with itself. Pinning a keys directory obtained elsewhere is
// what makes the check independent; see VERIFY.md.
type Keyring struct {
	src    record.Source
	prefix string
	logs   map[string]note.Verifier
	wit    map[string]*cosig.KeySet
}

// NewKeyring reads keys from src under prefix ("keys/" inside a repository,
// or "" for a directory that holds only keys).
func NewKeyring(src record.Source, prefix string) *Keyring {
	return &Keyring{src: src, prefix: prefix, logs: map[string]note.Verifier{}, wit: map[string]*cosig.KeySet{}}
}

// Log returns the verifier of log's checkpoints, whose name must be origin.
func (k *Keyring) Log(log, origin string) (note.Verifier, error) {
	if v, ok := k.logs[log]; ok {
		return v, matchName(v.Name(), origin, log)
	}
	text, err := k.read("logs/" + log + ".vkey")
	if err != nil {
		return nil, err
	}
	v, err := note.NewVerifier(text)
	if err != nil {
		return nil, fmt.Errorf("%slogs/%s.vkey: %w", k.prefix, log, err)
	}
	k.logs[log] = v
	return v, matchName(v.Name(), origin, log)
}

// Witness returns the keys of the primary witness; name, when not empty, is
// the name the key that signed must carry.
func (k *Keyring) Witness(name string) (*cosig.KeySet, error) {
	return k.WitnessKeys(record.WitnessEurope, name)
}

// WitnessKeys returns the keys of the named witness: its current key and the
// keys it replaced. name, when not empty, is the name the record says its
// signature carries, and one of the keys must carry it. An error that
// Is(record.ErrNotExist) says the key file is not there.
func (k *Keyring) WitnessKeys(witness, name string) (*cosig.KeySet, error) {
	set, ok := k.wit[witness]
	if !ok {
		file := WitnessKeyFileOf(witness)
		text, err := k.read(file)
		if err != nil {
			return nil, err
		}
		if set, err = cosig.ParseKeys(text); err != nil {
			return nil, fmt.Errorf("%s%s: %w", k.prefix, file, err)
		}
		k.wit[witness] = set
	}
	if name == "" {
		return set, nil
	}
	return set, matchWitnessName(set, name)
}

// OptionalWitnessKeys is WitnessKeys with the placeholder rule: the keys of a
// witness other than the primary one may not be published yet, and until they
// are the keys are absent, which is not a failure of the record they would
// verify. absent is true, with a nil error, when the file does not exist. The
// primary witness's key is never optional, and a key file that exists but is
// wrong is an error.
func (k *Keyring) OptionalWitnessKeys(witness, name string) (set *cosig.KeySet, absent bool, err error) {
	set, err = k.WitnessKeys(witness, name)
	if err != nil && witness != record.WitnessEurope && errors.Is(err, record.ErrNotExist) {
		return nil, true, nil
	}
	return set, false, err
}

func (k *Keyring) read(name string) (string, error) {
	b, err := k.src.Read(k.prefix + name)
	if err != nil {
		return "", fmt.Errorf("key %s%s: %w", k.prefix, name, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func matchName(got, want, what string) error {
	if got != want {
		return fmt.Errorf("the %s key is named %q, but the record says %q", what, got, want)
	}
	return nil
}

// matchWitnessName checks the name a record gives its witness's signature
// against the names in the key file. After a rotation the record of an older
// signature names an older key, which the file still lists.
func matchWitnessName(set *cosig.KeySet, want string) error {
	names := set.Names()
	if slices.Contains(names, want) {
		return nil
	}
	if len(names) == 1 {
		return matchName(names[0], want, "witness")
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	return fmt.Errorf("the witness keys are named %s, but the record says %q", strings.Join(quoted, ", "), want)
}
