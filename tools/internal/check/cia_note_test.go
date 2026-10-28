package check

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/cosig"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

const (
	testSlot     = "2026-10-01T14:20:00Z"
	testMeasured = `{"witness":"latam","slot":"2026-10-01T14:20:00Z","probes":{"vault":{"code":"ok"}}}`
)

func signNote(t testing.TB, k testKey, witness, slot, request, measured string) string {
	t.Helper()
	text := fmt.Sprintf("%s\nwitness %s\nslot %s\nrequest %s\nmeasured %s\n", measurementHeader, witness, slot, request, measured)
	signed, err := note.Sign(&note.Note{Text: text}, k.signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func TestMeasurementDigestIsOverTheCanonicalJSON(t *testing.T) {
	a, err1 := measurementDigest([]byte(`{"b": 1, "a": [true, null, "x"]}`))
	b, err2 := measurementDigest([]byte("{\n\t\"a\":[true,null,\"x\"],\"b\":1\n}"))
	if err1 != nil || err2 != nil || a != b || !hexRE.MatchString(a) {
		t.Errorf("layout and key order must not matter: %s %s %v %v", a, b, err1, err2)
	}
	if c, _ := measurementDigest([]byte(`{"a":[true,null,"x"],"b":2}`)); c == a {
		t.Error("another value, the same digest")
	}
	if _, err := measurementDigest([]byte(`{"a":1.5}`)); err == nil {
		t.Error("a number with a fraction has no canonical form here")
	}
}

func TestParseMeasurement(t *testing.T) {
	hex := strings.Repeat("ab", 32)
	good := fmt.Sprintf("%s\nwitness latam\nslot %s\nrequest %s\nmeasured %s\n", measurementHeader, testSlot, hex, hex)
	for _, c := range []struct {
		name string
		text string
		ok   bool
	}{
		{"a request digest", good, true},
		{"the primary answers no request", strings.Replace(good, "request "+hex, "request none", 1), true},
		{"another header", strings.Replace(good, "measurement/v1", "request/v1", 1), false},
		{"a sixth line", good + "extra x\n", false},
		{"no final newline", strings.TrimSuffix(good, "\n"), false},
		{"lines swapped", strings.Replace(strings.Replace(good, "witness latam", "TMP", 1), "slot "+testSlot, "witness latam", 1), false},
		{"two values on a line", strings.Replace(good, "witness latam", "witness latam europe", 1), false},
		{"an empty value", strings.Replace(good, "witness latam", "witness ", 1), false},
		{"a measured digest in capitals", strings.Replace(good, "measured "+hex, "measured "+strings.ToUpper(hex), 1), false},
		{"a short digest", strings.Replace(good, "measured "+hex, "measured abc", 1), false},
		{"a witness id that is not one", strings.Replace(good, "witness latam", "witness Latam", 1), false},
		{"nothing", "", false},
	} {
		if _, err := parseMeasurement(c.text); (err == nil) != c.ok {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
}

func FuzzParseMeasurement(f *testing.F) {
	hex := strings.Repeat("0f", 32)
	f.Add(fmt.Sprintf("%s\nwitness latam\nslot %s\nrequest %s\nmeasured %s\n", measurementHeader, testSlot, hex, hex))
	f.Add(fmt.Sprintf("%s\nwitness europe\nslot %s\nrequest none\nmeasured %s\n", measurementHeader, testSlot, hex))
	f.Add("")
	f.Add(measurementHeader + "\n\n\n\n\n\n")
	f.Fuzz(func(t *testing.T, text string) {
		m, err := parseMeasurement(text)
		if err != nil {
			return
		}
		// What is accepted is exactly the one spelling the format has.
		again := fmt.Sprintf("%s\nwitness %s\nslot %s\nrequest %s\nmeasured %s\n", measurementHeader, m.witness, m.slot, m.request, m.measured)
		if again != text {
			t.Errorf("accepted %q, which is not its own canonical spelling %q", text, again)
		}
	})
}

// The signed note of a measurement is held to its entry and to its run.
func TestCheckMeasurementNote(t *testing.T) {
	latam := newTestKey(t, "witness.example/latam/v1", "latam")
	europe := newTestKey(t, "witness.example/auditor/v1", "europe")
	other := newTestKey(t, "witness.example/latam/v1", "someone else")
	digest, err := measurementDigest([]byte(testMeasured))
	if err != nil {
		t.Fatal(err)
	}
	request := strings.Repeat("c", 64)
	entry := func(note string) record.WitnessEntry {
		return record.WitnessEntry{Status: "ok", Note: &note, MeasuredRaw: []byte(testMeasured)}
	}
	for _, c := range []struct {
		name      string
		id        string
		keys      *Keyring
		note      string
		wantWorst Status
		want      string
	}{
		{"a valid note", "latam", keysWith(map[string]testKey{"latam": latam}), signNote(t, latam, "latam", testSlot, request, digest), OK, "agree with the entry"},
		{"the primary's valid note", "europe", keysWith(map[string]testKey{"europe": europe}), signNote(t, europe, "europe", testSlot, "none", digest), OK, "agree with the entry"},
		{"the measurement was changed after it was signed", "latam", keysWith(map[string]testKey{"latam": latam}), signNote(t, latam, "latam", testSlot, request, strings.Repeat("0", 64)), Fail, "changed after it was signed"},
		{"a note of another slot moved here", "latam", keysWith(map[string]testKey{"latam": latam}), signNote(t, latam, "latam", "2026-10-01T14:15:00Z", request, digest), Fail, "cannot be moved to another run"},
		{"a note of another witness", "latam", keysWith(map[string]testKey{"latam": latam}), signNote(t, latam, "europe", testSlot, request, digest), Fail, "statement by europe"},
		{"signed with another key", "latam", keysWith(map[string]testKey{"latam": latam}), signNote(t, other, "latam", testSlot, request, digest), Fail, "does not verify"},
		{"signed by Europe's key in Latin America's name", "latam", keysWith(map[string]testKey{"latam": latam}), signNote(t, europe, "latam", testSlot, request, digest), Fail, "does not verify"},
		{"no request digest from a witness that answers a request", "latam", keysWith(map[string]testKey{"latam": latam}), signNote(t, latam, "latam", testSlot, "none", digest), Fail, "by digest"},
		{"the primary names a request it never had", "europe", keysWith(map[string]testKey{"europe": europe}), signNote(t, europe, "europe", testSlot, request, digest), Fail, "answers no request"},
		{"not a note", "latam", keysWith(map[string]testKey{"latam": latam}), "just text\n", Fail, "malformed"},
		{"a note that signs another text", "latam", keysWith(map[string]testKey{"latam": latam}), signRaw(t, latam, "hello\nworld\n"), Fail, "five lines"},
		// The placeholder rule: a key that is not published yet is absent, which is not a failure.
		{"latam's key is not published yet: unsigned, and said so", "latam", keysWith(nil), signNote(t, latam, "latam", testSlot, request, digest), Warn, "not published yet"},
		{"without the key the lines are still held to the entry", "latam", keysWith(nil), signNote(t, latam, "latam", "2026-10-01T14:15:00Z", request, digest), Fail, "cannot be moved"},
		{"without the key a changed measurement still shows", "latam", keysWith(nil), signNote(t, latam, "latam", testSlot, request, strings.Repeat("0", 64)), Fail, "changed after it was signed"},
		{"the primary's key is never optional", "europe", keysWith(nil), signNote(t, europe, "europe", testSlot, "none", digest), Fail, "does not exist"},
	} {
		r := &Report{Subject: "run"}
		checkMeasurementNote(c.keys, c.id, entry(c.note), testSlot, r)
		var text strings.Builder
		r.Print(&text, false)
		if r.Worst() != c.wantWorst || !strings.Contains(text.String(), c.want) {
			t.Errorf("%s: worst %v, want %v containing %q:\n%s", c.name, r.Worst(), c.wantWorst, c.want, text.String())
		}
	}
}

func signRaw(t testing.TB, k testKey, text string) string {
	t.Helper()
	signed, err := note.Sign(&note.Note{Text: text}, k.signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// A key file that exists but is not a key is an error even for a witness whose
// key may be missing, and a key with another name than the note's does not verify.
func TestOptionalWitnessKey(t *testing.T) {
	good := newTestKey(t, "witness.example/latam/v1", "latam")
	for _, c := range []struct {
		name    string
		src     memSource
		witness string
		absent  bool
		wantErr string
	}{
		{"published", memSource{"keys/witness/latam.vkey": []byte(good.vkey + "\n")}, "latam", false, ""},
		{"not published yet", memSource{}, "latam", true, ""},
		{"the primary's is never optional", memSource{}, "europe", false, "does not exist"},
		{"primary's file name", memSource{"keys/witness/auditor.vkey": []byte(good.vkey)}, "europe", false, ""},
		{"a file that is not a key", memSource{"keys/witness/latam.vkey": []byte("TODO\n")}, "latam", false, "malformed witness vkey"},
		{"a key whose hash does not match", memSource{"keys/witness/latam.vkey": []byte(strings.Replace(good.vkey, "+", "+00", 1))}, "latam", false, "malformed"},
	} {
		v, absent, err := NewKeyring(c.src, "keys/").OptionalWitnessKey(c.witness, "")
		switch {
		case absent != c.absent, (err == nil) != (c.wantErr == ""), err != nil && !strings.Contains(err.Error(), c.wantErr):
			t.Errorf("%s: key %v absent %v err %v", c.name, v != nil, absent, err)
		}
	}
	if _, _, err := NewKeyring(memSource{"keys/witness/latam.vkey": []byte(good.vkey)}, "keys/").OptionalWitnessKey("latam", "witness.example/other/v1"); err == nil {
		t.Error("a key with another name than the one asked for was accepted")
	}
}

// Whatever a note is turned into, it is never accepted with another text than
// the one that was signed.
func FuzzOpenMeasurement(f *testing.F) {
	key := newTestKey(f, "witness.example/latam/v1", "latam")
	digest, _ := measurementDigest([]byte(testMeasured))
	valid := signNote(f, key, "latam", testSlot, strings.Repeat("c", 64), digest)
	signedText, _, _ := strings.Cut(valid, "\n\n")
	signedText += "\n"
	verifier, err := cosig.NewVerifier(key.vkey)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(valid + "\u2014 other AAAAAAAA\n")
	f.Add(strings.Replace(valid, "slot 2026", "slot 2027", 1))
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		text, err := openMeasurement(verifier, false, s)
		if err == nil && text != signedText {
			t.Errorf("accepted %q with the text %q, not the signed one %q", s, text, signedText)
		}
		// Without the key the text is read as it stands: it must not panic, whatever it is.
		_, _ = openMeasurement(verifier, true, s)
	})
}
