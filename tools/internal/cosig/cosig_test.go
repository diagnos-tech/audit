package cosig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

// A cosigned note checked against github.com/transparency-dev/formats/note
// (NewVerifierForCosignatureV1, VKeyToCosignatureV1 and CoSigV1Timestamp at
// v0.0.0-20251208091212-1378f9e1b1b7), which the witness uses to sign.
const (
	goldenVKey = "witness.example/x+e8725898+BOmbJyq5zTPkK8F48YyPdidFel1QtY00luJen2LbpHUs"
	goldenNote = "example.com/log\n42\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n" +
		"— witness.example/x 6HJYmAAAAABq3gyPrFNCGYsokmQ7qRr7IF5x4yJrq0MLaOu86fEePfQz814QjKjsxWCWEXI3k/xbomn+iHkR/r8JDUsbG0bpo40QDQ==\n"
	// The same key as a plain Ed25519 (0x01) vkey.
	goldenPlainVKey = "witness.example/x+3c3701b4+AembJyq5zTPkK8F48YyPdidFel1QtY00luJen2LbpHUs"
)

var goldenTime = time.Date(2026, 10, 25, 14, 5, 3, 0, time.UTC)

func TestGolden(t *testing.T) {
	v, err := NewVerifier(goldenVKey)
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Open([]byte(goldenNote), note.VerifierList(v))
	if err != nil {
		t.Fatalf("golden cosignature rejected: %v", err)
	}
	if got, err := Time(n.Sigs[0]); err != nil || !got.Equal(goldenTime) {
		t.Errorf("Time = %v, %v; want %v", got, err, goldenTime)
	}
	if v.VKey() != goldenVKey {
		t.Errorf("VKey() = %s", v.VKey())
	}
}

func TestPlainVKeyIsTheSameWitness(t *testing.T) {
	plain, err := NewVerifier(goldenPlainVKey)
	if err != nil {
		t.Fatal(err)
	}
	if plain.VKey() != goldenVKey {
		t.Errorf("plain vkey maps to %s, want %s", plain.VKey(), goldenVKey)
	}
}

func TestRoundTrip(t *testing.T) {
	seed := sha256.Sum256([]byte("cosig test"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	signer := NewSigner("witness.example/t", priv, func() time.Time { return at })
	v, err := NewVerifier(VKey("witness.example/t", priv.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	body := "log.example/v1\n7\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
	msg, err := note.Sign(&note.Note{Text: body}, signer)
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Open(msg, note.VerifierList(v))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := Time(n.Sigs[0]); !got.Equal(at) {
		t.Errorf("Time = %v, want %v", got, at)
	}

	// Any change to the body breaks the cosignature.
	tampered := strings.Replace(string(msg), "\n7\n", "\n8\n", 1)
	if _, err := note.Open([]byte(tampered), note.VerifierList(v)); err == nil {
		t.Error("tampered note verified")
	}
}

func TestRejectsMalformedVKeys(t *testing.T) {
	for _, vkey := range []string{
		"",
		"witness.example/x",
		"witness.example/x+e8725898",
		"witness.example/x+00000000+BOmbJyq5zTPkK8F48YyPdidFel1QtY00luJen2LbpHUs", // wrong hash
		"witness.example/x+e8725898+BOmbJyq5zTPkK8F48YyPdidFel1QtY00luJen2LbpH",   // short key
		"witness.example/x+e8725898+AumbJyq5zTPkK8F48YyPdidFel1QtY00luJen2LbpHUs", // unknown alg 0x02
		"bad name+e8725898+BOmbJyq5zTPkK8F48YyPdidFel1QtY00luJen2LbpHUs",
	} {
		if _, err := NewVerifier(vkey); err == nil {
			t.Errorf("NewVerifier(%q) succeeded", vkey)
		}
	}
}
