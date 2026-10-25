package check

import (
	"fmt"
	"strings"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/cosig"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// WitnessKeyFile is the witness key's file under the keys directory.
const WitnessKeyFile = "witness/auditor.vkey"

// Keyring loads verifier keys on demand from a keys directory laid out like
// keys/ in the repository: logs/<log>.vkey and witness/auditor.vkey.
//
// Keys read from the repository under check only prove that the repository
// is consistent with itself. Pinning a keys directory obtained elsewhere is
// what makes the check independent; see VERIFY.md.
type Keyring struct {
	src    record.Source
	prefix string
	logs   map[string]note.Verifier
	wit    *cosig.Verifier
}

// NewKeyring reads keys from src under prefix ("keys/" inside a repository,
// or "" for a directory that holds only keys).
func NewKeyring(src record.Source, prefix string) *Keyring {
	return &Keyring{src: src, prefix: prefix, logs: map[string]note.Verifier{}}
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

// Witness returns the witness verifier, whose name must be name.
func (k *Keyring) Witness(name string) (*cosig.Verifier, error) {
	if k.wit == nil {
		text, err := k.read(WitnessKeyFile)
		if err != nil {
			return nil, err
		}
		v, err := cosig.NewVerifier(text)
		if err != nil {
			return nil, fmt.Errorf("%s%s: %w", k.prefix, WitnessKeyFile, err)
		}
		k.wit = v
	}
	return k.wit, matchName(k.wit.Name(), name, "witness")
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
