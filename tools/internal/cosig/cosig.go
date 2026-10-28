// Package cosig implements the timestamped Ed25519 witness cosignature of
// C2SP tlog-cosignature (algorithm 0x04, "cosignature/v1") on top of
// golang.org/x/mod/sumdb/note, which only knows plain Ed25519 (0x01).
//
// It mirrors NewVerifierForCosignatureV1 from
// github.com/transparency-dev/formats/note so that this repository's tools
// need no dependency besides x/mod. The cross-check against that package
// lives in the tests.
//
// A cosignature line is "— <name> base64(keyhash[4] || time[8] || sig[64])",
// and the Ed25519 signature covers
//
//	cosignature/v1
//	time <decimal unix seconds>
//	<the checkpoint body, every line of it>
package cosig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/mod/sumdb/note"
)

const (
	algEd25519   = 0x01 // plain signed-note Ed25519
	algCosigV1   = 0x04 // tlog-cosignature cosignature/v1
	timeSize     = 8
	keyHashBytes = 4
)

// Verifier checks cosignature/v1 lines for one witness key.
type Verifier struct {
	name string
	hash uint32
	pub  ed25519.PublicKey
}

var _ note.Verifier = (*Verifier)(nil)

// NewVerifier parses a witness vkey, "<name>+<hash>+<base64(alg || pubkey)>".
// The C2SP encoding uses alg 0x04; a plain Ed25519 (0x01) vkey of the same
// key is accepted too, as transparency-dev/formats does. Unlike that package,
// the key hash written in the vkey must match the key.
func NewVerifier(vkey string) (*Verifier, error) {
	name, rest, _ := strings.Cut(strings.TrimSpace(vkey), "+")
	hash16, key64, _ := strings.Cut(rest, "+")
	key, err := base64.StdEncoding.DecodeString(key64)
	if err != nil || len(hash16) != 8 || !validName(name) || len(key) != 1+ed25519.PublicKeySize {
		return nil, fmt.Errorf("cosig: malformed witness vkey %q", vkey)
	}
	written, err := strconv.ParseUint(hash16, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("cosig: malformed key hash in vkey %q", vkey)
	}
	alg, pub := key[0], ed25519.PublicKey(key[1:])
	if alg != algCosigV1 && alg != algEd25519 {
		return nil, fmt.Errorf("cosig: vkey %q has algorithm %#x, want 0x04 (cosignature/v1)", name, alg)
	}
	if uint32(written) != keyHash(name, alg, pub) {
		return nil, fmt.Errorf("cosig: key hash in vkey %q does not match its key", name)
	}
	return &Verifier{name: name, hash: keyHash(name, algCosigV1, pub), pub: pub}, nil
}

// Name returns the witness name.
func (v *Verifier) Name() string { return v.name }

// KeyHash returns the cosignature/v1 key hash (always computed with 0x04).
func (v *Verifier) KeyHash() uint32 { return v.hash }

// Verify reports whether sig (time || ed25519 signature) is a valid
// cosignature of the note body msg.
func (v *Verifier) Verify(msg, sig []byte) bool {
	if len(sig) != timeSize+ed25519.SignatureSize {
		return false
	}
	t := binary.BigEndian.Uint64(sig)
	m, err := signedMessage(t, msg)
	if err != nil {
		return false
	}
	return ed25519.Verify(v.pub, m, sig[timeSize:])
}

// NoteVerifier returns the plain signed-note verifier (algorithm 0x01) of the
// same key. A witness signs two kinds of text with one key: checkpoints, as
// cosignature/v1, and its own statements (a measurement) as ordinary signed
// notes; the verifier of the second kind is derived from the first, so the
// repository publishes one key per witness.
func (v *Verifier) NoteVerifier() (note.Verifier, error) {
	vkey, err := note.NewEd25519VerifierKey(v.name, v.pub)
	if err != nil {
		return nil, err
	}
	return note.NewVerifier(vkey)
}

// VKey returns the C2SP vkey (alg 0x04) for this verifier.
func (v *Verifier) VKey() string { return VKey(v.name, v.pub) }

// VKey encodes an Ed25519 public key as a cosignature/v1 vkey.
func VKey(name string, pub ed25519.PublicKey) string {
	key := append([]byte{algCosigV1}, pub...)
	return fmt.Sprintf("%s+%08x+%s", name, keyHash(name, algCosigV1, pub), base64.StdEncoding.EncodeToString(key))
}

// Time extracts the timestamp a witness put inside its cosignature.
func Time(sig note.Signature) (time.Time, error) {
	raw, err := base64.StdEncoding.DecodeString(sig.Base64)
	if err != nil || len(raw) != keyHashBytes+timeSize+ed25519.SignatureSize {
		return time.Time{}, errors.New("cosig: not a cosignature/v1 signature")
	}
	secs := binary.BigEndian.Uint64(raw[keyHashBytes:])
	if secs > 1<<62 {
		return time.Time{}, errors.New("cosig: timestamp out of range")
	}
	return time.Unix(int64(secs), 0).UTC(), nil
}

// Signer produces cosignature/v1 signatures. Only the example generator uses
// it: the real witness signs with transparency-dev/formats.
type Signer struct {
	name string
	hash uint32
	priv ed25519.PrivateKey
	now  func() time.Time
}

var _ note.Signer = (*Signer)(nil)

// NewSigner returns a Signer for priv that stamps each signature with now().
func NewSigner(name string, priv ed25519.PrivateKey, now func() time.Time) *Signer {
	pub := priv.Public().(ed25519.PublicKey)
	return &Signer{name: name, hash: keyHash(name, algCosigV1, pub), priv: priv, now: now}
}

func (s *Signer) Name() string    { return s.name }
func (s *Signer) KeyHash() uint32 { return s.hash }

func (s *Signer) Sign(msg []byte) ([]byte, error) {
	t := uint64(s.now().Unix())
	m, err := signedMessage(t, msg)
	if err != nil {
		return nil, err
	}
	sig := binary.BigEndian.AppendUint64(make([]byte, 0, timeSize+ed25519.SignatureSize), t)
	return append(sig, ed25519.Sign(s.priv, m)...), nil
}

// signedMessage builds the bytes a cosignature/v1 signature covers.
func signedMessage(t uint64, body []byte) ([]byte, error) {
	// A checkpoint has at least origin, size and root hash lines.
	if strings.Count(string(body), "\n") < 3 {
		return nil, errors.New("cosig: checkpoint body has fewer than three lines")
	}
	return fmt.Appendf(nil, "cosignature/v1\ntime %d\n%s", t, body), nil
}

// keyHash is the signed-note key ID: SHA-256(name || "\n" || alg || key)[:4].
func keyHash(name string, alg byte, pub ed25519.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', alg})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// validName follows signed-note: non-empty, valid UTF-8, no spaces, no '+'.
func validName(name string) bool {
	return name != "" && utf8.ValidString(name) &&
		strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}
