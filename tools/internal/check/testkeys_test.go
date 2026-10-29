package check

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

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

// testKey is a key derived from a label, with the signer of its notes and its
// vkey in the form keys/witness publishes (vkey) and as a plain signed-note
// key (plain), which is how a log's key is published.
type testKey struct {
	name   string
	priv   ed25519.PrivateKey
	signer note.Signer
	vkey   string
	plain  string
}

// cosigner signs checkpoints as cosignature/v1, stamped with at.
func (k testKey) cosigner(at time.Time) note.Signer {
	return cosig.NewSigner(k.name, k.priv, func() time.Time { return at })
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
	return testKey{name: name, priv: priv, signer: signer, vkey: cosig.VKey(name, pub), plain: vkey}
}

// keysWith is a keyring over a repository that publishes the given witness keys.
func keysWith(published map[string]testKey) *Keyring {
	src := memSource{}
	for id, k := range published {
		src["keys/"+WitnessKeyFileOf(id)] = []byte(k.vkey + "\n")
	}
	return NewKeyring(src, "keys/")
}

// keyFile is the text of a witness key file that lists the keys, the current
// one first, one per line.
func keyFile(keys ...testKey) string {
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k.vkey + "\n")
	}
	return b.String()
}

// keysWithFile is a keyring over a repository whose key file of the witness
// holds exactly text.
func keysWithFile(witness, text string) *Keyring {
	return NewKeyring(memSource{"keys/" + WitnessKeyFileOf(witness): []byte(text)}, "keys/")
}
