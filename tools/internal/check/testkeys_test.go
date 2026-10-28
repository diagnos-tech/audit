package check

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/cosig"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// memSource is a repository in memory.
type memSource map[string][]byte

func (m memSource) Read(p string) ([]byte, error) {
	if b, ok := m[p]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("%w: %s", record.ErrNotExist, p)
}

func (m memSource) String() string { return "memory" }

// testKey is a witness key derived from a label, with the signer of its notes
// and its vkey in the form keys/witness publishes.
type testKey struct {
	name   string
	signer note.Signer
	vkey   string
}

func newTestKey(t testing.TB, name, label string) testKey {
	t.Helper()
	seed := sha256.Sum256([]byte("check test key: " + label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	vkey, err := note.NewEd25519VerifierKey(name, pub)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(append([]byte(name+"\n\x01"), pub...))
	skey := fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, binary.BigEndian.Uint32(h[:]), base64.StdEncoding.EncodeToString(append([]byte{1}, priv.Seed()...)))
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	_ = vkey
	return testKey{name: name, signer: signer, vkey: cosig.VKey(name, pub)}
}

// keysWith is a keyring over a repository that publishes the given witness keys.
func keysWith(published map[string]testKey) *Keyring {
	src := memSource{}
	for id, k := range published {
		src["keys/"+WitnessKeyFileOf(id)] = []byte(k.vkey + "\n")
	}
	return NewKeyring(src, "keys/")
}
