package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

type ed25519PublicKey = ed25519.PublicKey

func noteVerifier(vkey string) (note.Verifier, error) { return note.NewVerifier(vkey) }

// writer puts files under the output root by their repository path.
type writer struct{ root string }

// json writes a data file the way the witness does and returns its bytes,
// whose SHA-256 later records pin.
func (w *writer) json(path string, v any) ([]byte, error) {
	data, err := record.Encode(v)
	if err != nil {
		return nil, err
	}
	return data, w.raw(path, data)
}

func (w *writer) text(path, s string) error { return w.raw(path, []byte(s)) }

func (w *writer) raw(path string, data []byte) error {
	full := filepath.Join(w.root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	return os.WriteFile(full, data, 0o644)
}
