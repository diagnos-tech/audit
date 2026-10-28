package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/jcs"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// canonicalDigest is the SHA-256 of the RFC 8785 canonical JSON of v.
func canonicalDigest(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Canonicalize(raw)
	if err != nil {
		return "", err
	}
	d := sha256.Sum256(canonical)
	return hex.EncodeToString(d[:]), nil
}

// signMeasurement writes a witness's signed statement about its measurement:
// the slot, the request it answers (none for the primary witness, which answers
// no one) and the digest of the canonical JSON of what it measured.
func signMeasurement(signer note.Signer, witness, slot, request string, m record.Measured) (string, error) {
	digest, err := canonicalDigest(m)
	if err != nil {
		return "", err
	}
	text := fmt.Sprintf("diagnos-witness/measurement/v1\nwitness %s\nslot %s\nrequest %s\nmeasured %s\n", witness, slot, request, digest)
	signed, err := note.Sign(&note.Note{Text: text}, signer)
	return string(signed), err
}

// signRequest writes the primary's signed request to the secondary: which slot
// it wants measured, when it was sent, until when an answer is of use, and the
// digest of what the primary last committed of the secondary's measurements, so
// that the secondary knows what to send again. The note is not published; its
// digest is what the secondary's measurement names.
func signRequest(signer note.Signer, slot, sent time.Time, prev string) (string, error) {
	text := fmt.Sprintf("diagnos-witness/request/v1\nwitness latam\nslot %s\nsent %s\ndeadline %s\nprev %s\n",
		record.FormatTime(slot), record.FormatTime(sent), record.FormatTime(sent.Add(40*time.Second)), prev)
	signed, err := note.Sign(&note.Note{Text: text}, signer)
	return string(signed), err
}

func digestOf(s string) string {
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:])
}
