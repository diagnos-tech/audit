package check

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/cosig"
	"github.com/diagnos-tech/audit/tools/internal/jcs"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// measurementHeader is the first line of the text a witness signs over its
// measurement. A signature over it can never be mistaken for a cosignature or a
// checkpoint signature: neither starts with these words.
const measurementHeader = "diagnos-witness/measurement/v1"

var (
	hexRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	witnessRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,15}$`)
)

// measurement is the text of a measurement note.
type measurement struct {
	witness  string
	slot     string
	request  string // the SHA-256 of the request note, or "none" for the primary witness
	measured string // the SHA-256 of the canonical JSON of measured
}

// parseMeasurement reads the five lines of a measurement note, and nothing
// else: header, witness, slot, request and measured, each ending in a newline.
func parseMeasurement(text string) (measurement, error) {
	lines := strings.Split(text, "\n")
	if len(lines) != 6 || lines[5] != "" || lines[0] != measurementHeader {
		return measurement{}, fmt.Errorf("the text is not the five lines of a %s note", measurementHeader)
	}
	var m measurement
	for i, field := range []struct {
		key string
		dst *string
	}{{"witness ", &m.witness}, {"slot ", &m.slot}, {"request ", &m.request}, {"measured ", &m.measured}} {
		value, ok := strings.CutPrefix(lines[i+1], field.key)
		if !ok || value == "" || strings.ContainsAny(value, " \t") {
			return measurement{}, fmt.Errorf("line %d should be %q followed by one value", i+2, strings.TrimSpace(field.key))
		}
		*field.dst = value
	}
	if !witnessRE.MatchString(m.witness) || !hexRE.MatchString(m.measured) || (m.request != "none" && !hexRE.MatchString(m.request)) {
		return measurement{}, errors.New("the witness, request or measured value is malformed")
	}
	return m, nil
}

// measurementDigest is the SHA-256 of the RFC 8785 canonical JSON of the
// measured object, the way the file spells it.
func measurementDigest(measuredRaw []byte) (string, error) {
	canonical, err := jcs.Canonicalize(measuredRaw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// checkMeasurementNote verifies the signed note of one witness's entry against
// the entry and the run: the signature, then the witness, the slot, the
// request and the digest of what was measured. A witness other than the primary
// one may have no key published yet; then the note is read as it stands, its
// lines are still held to the entry, and the report says that nobody checked
// the signature.
func checkMeasurementNote(keys *Keyring, id string, e record.WitnessEntry, slot string, r *Report) {
	witKeys, absent, err := keys.OptionalWitnessKeys(id, "")
	if err != nil {
		r.fail("note "+id, "%v", err)
		return
	}
	text, signer, err := openMeasurement(witKeys, absent, *e.Note)
	if err != nil {
		r.fail("note "+id, "%v", err)
		return
	}
	m, err := parseMeasurement(text)
	if err != nil {
		r.fail("note "+id, "%v", err)
		return
	}
	digest, err := measurementDigest(e.MeasuredRaw)
	wantRequest := "none"
	switch {
	case err != nil:
		r.fail("note "+id, "cannot canonicalize measured: %v", err)
	case m.witness != id:
		r.fail("note "+id, "the note is a statement by %s", m.witness)
	case m.slot != slot:
		r.fail("note "+id, "the note is about slot %s, not %s: a measurement cannot be moved to another run", m.slot, slot)
	case m.measured != digest:
		r.fail("note "+id, "the note signs measured %s, but the measured object hashes to %s: it was changed after it was signed", m.measured, digest)
	case id != record.WitnessEurope && !hexRE.MatchString(m.request):
		r.fail("note "+id, "a witness that answers a request names it by digest, not %q", m.request)
	case id == record.WitnessEurope && m.request != wantRequest:
		r.fail("note "+id, "the primary witness answers no request, but the note names %q", m.request)
	case absent:
		r.warn("note "+id, "slot, request and measured digest agree with the entry; the signature is not checked: %s is not published yet", WitnessKeyFileOf(id))
	default:
		r.pass("note "+id, "signed by %s; slot, request and measured digest %s agree with the entry", signer, short(digest))
	}
}

// openMeasurement returns the text of the note and the name of the key that
// signed it: verified with one of the witness's keys, the current one or one
// it replaced, or, without the keys, as the note states it (and then there is
// no signer to name).
func openMeasurement(keys *cosig.KeySet, absent bool, text string) (body, signer string, err error) {
	if absent {
		_, err := note.Open([]byte(text), nil)
		var unverified *note.UnverifiedNoteError
		if errors.As(err, &unverified) {
			return unverified.Note.Text, "", nil
		}
		return "", "", fmt.Errorf("the note is malformed: %v", err)
	}
	vs, err := keys.NoteVerifiers()
	if err != nil {
		return "", "", err
	}
	n, err := note.Open([]byte(text), note.VerifierList(vs...))
	if err != nil {
		return "", "", fmt.Errorf("the signature does not verify with %s: %v", keyNames(vs), err)
	}
	return n.Text, n.Sigs[0].Name, nil
}
