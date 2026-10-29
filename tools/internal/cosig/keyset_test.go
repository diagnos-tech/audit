package cosig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

// exampleKey derives a key from a label: the tests make their keys when they
// run, and nothing secret is kept in a file.
func exampleKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("cosig key set test: " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func exampleVKey(name, label string) string {
	return VKey(name, exampleKey(label).Public().(ed25519.PublicKey))
}

const (
	latamV1 = "witness.example/latam/v1"
	latamV2 = "witness.example/latam/v2"
	europe1 = "witness.example/auditor/v1"
)

func TestFamily(t *testing.T) {
	for name, want := range map[string]string{
		"witness.example/latam/v1":   "witness.example/latam",
		"witness.example/latam/v2":   "witness.example/latam",
		"witness.example/latam/v12":  "witness.example/latam",
		"witness.example/latam":      "witness.example/latam", // no version: its own family
		"witness.example/latam/v":    "witness.example/latam/v",
		"witness.example/latam/v1x":  "witness.example/latam/v1x",
		"witness.example/latam/v1/a": "witness.example/latam/v1/a",
		"witness.example/auditor/v1": "witness.example/auditor",
	} {
		if got := Family(name); got != want {
			t.Errorf("Family(%q) = %q, want %q", name, got, want)
		}
	}
}

// A file with one key, with or without a final newline, with the line ending of
// another system, with space around the key, with blank lines around it, is one key.
func TestParseKeysSingleKey(t *testing.T) {
	v1 := exampleVKey(latamV1, "latam 1")
	for name, text := range map[string]string{
		"bare":                 v1,
		"newline":              v1 + "\n",
		"CRLF":                 v1 + "\r\n",
		"padded":               "  \t" + v1 + " \n",
		"blank lines around":   "\n\n" + v1 + "\n\n\n",
		"blank lines of space": " \n" + v1 + "\n \t \n",
	} {
		set, err := ParseKeys(text)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(set.Keys()) != 1 || set.Current().VKey() != v1 || set.Family() != "witness.example/latam" {
			t.Errorf("%s: keys %v, current %s", name, set.Names(), set.Current().VKey())
		}
	}
}

// What a single-line file says when it is wrong is what it has always said: the
// keyring trimmed the file and handed it to NewVerifier.
func TestParseKeysSingleKeyErrorsAreUnchanged(t *testing.T) {
	good := exampleVKey(latamV1, "latam 1")
	for _, text := range []string{
		"TODO\n",
		"pending",
		"witness.example/latam/v1",
		strings.Replace(good, "+", "+00", 1),
		strings.Replace(good, "+", "+ffffffff+", 1),
		"bad name+e8725898+BOmbJyq5zTPkK8F48YyPdidFel1QtY00luJen2LbpHUs",
	} {
		_, want := NewVerifier(strings.TrimSpace(text))
		_, got := ParseKeys(strings.TrimSpace(text))
		if want == nil || got == nil || got.Error() != want.Error() {
			t.Errorf("ParseKeys(%q): %v, but NewVerifier says %v", text, got, want)
		}
	}
}

// After a rotation the file lists the new key first and the keys it replaced after it.
func TestParseKeysCurrentAndPrevious(t *testing.T) {
	v2, v1 := exampleVKey(latamV2, "latam 2"), exampleVKey(latamV1, "latam 1")
	for name, text := range map[string]string{
		"plain":              v2 + "\n" + v1 + "\n",
		"no final newline":   v2 + "\n" + v1,
		"blank lines":        "\n" + v2 + "\n\n\n" + v1 + "\n\n",
		"padding and CRLF":   " " + v2 + " \r\n\t" + v1 + "\r\n",
		"previous in 0x01":   v2 + "\n" + plainForm(t, v1) + "\n",
		"three generations":  exampleVKey("witness.example/latam/v3", "latam 3") + "\n" + v2 + "\n" + v1,
		"an unversioned one": v2 + "\n" + exampleVKey("witness.example/latam", "latam 0"),
	} {
		set, err := ParseKeys(text)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if n := len(set.Keys()); n < 2 {
			t.Errorf("%s: %d keys", name, n)
		}
		if got := set.Current().Name(); got != set.Names()[0] || got == latamV1 {
			t.Errorf("%s: the current key is %s, want the first line", name, got)
		}
		if len(set.Verifiers()) != len(set.Keys()) {
			t.Errorf("%s: %d verifiers for %d keys", name, len(set.Verifiers()), len(set.Keys()))
		}
	}
	// The first line is the current key whatever the versions say.
	set, err := ParseKeys(v1 + "\n" + v2 + "\n")
	if err != nil || set.Current().Name() != latamV1 {
		t.Errorf("order of the file not kept: %v %v", err, set)
	}
}

// plainForm rewrites a cosignature/v1 vkey as the plain Ed25519 vkey of the same key.
func plainForm(t *testing.T, vkey string) string {
	t.Helper()
	v, err := NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := note.NewEd25519VerifierKey(v.name, v.pub)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func TestParseKeysRejects(t *testing.T) {
	v2, v1 := exampleVKey(latamV2, "latam 2"), exampleVKey(latamV1, "latam 1")
	europe := exampleVKey(europe1, "europe 1")
	for _, c := range []struct {
		name string
		text string
		want string // a part of the error
	}{
		{"an empty file", "", "has no key"},
		{"only blank lines", "\n \n\t\n", "has no key"},
		{"a malformed second line", v2 + "\nTODO\n", "line 2: cosig: malformed witness vkey"},
		{"a malformed first line", "TODO\n" + v1 + "\n", "line 1: cosig: malformed witness vkey"},
		{"the line number counts blank lines", "\n" + v2 + "\n\n" + "TODO\n", "line 4:"},
		{"a key hash that does not match", v2 + "\n" + strings.Replace(v1, "+", "+00", 1) + "\n", "line 2: cosig: malformed"},
		{"a hash of another key", v2 + "\n" + strings.Replace(v1, v1[len(latamV1)+1:len(latamV1)+9], "00000000", 1) + "\n", "line 2: cosig: key hash"},
		{"a comment", "# the previous key\n" + v2 + "\n", "line 1: cosig: malformed"},
		{"two keys on one line", v2 + " " + v1 + "\n", "cosig: malformed witness vkey"},
		{"a key of another witness listed after", v2 + "\n" + europe + "\n", `line 2: key "witness.example/auditor/v1" is not a key of witness.example/latam`},
		{"a key of another witness listed first", europe + "\n" + v2 + "\n", `line 2: key "witness.example/latam/v2" is not a key of witness.example/auditor`},
		{"a name that only starts like the witness", v2 + "\n" + exampleVKey("witness.example/latam-b/v1", "other") + "\n", "is not a key of witness.example/latam"},
		{"another host", v2 + "\n" + exampleVKey("witness.example.org/latam/v1", "other") + "\n", "is not a key of witness.example/latam"},
		{"the same key twice", v2 + "\n" + v1 + "\n" + v1 + "\n", `line 3: key "witness.example/latam/v1"`},
		{"the same key twice, side by side", v1 + "\n" + v1 + "\n", "is already listed on line 1"},
		{"the same key as a plain vkey too", v1 + "\n" + plainForm(t, v1) + "\n", "is already listed on line 1"},
	} {
		set, err := ParseKeys(c.text)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, set = %v; want an error with %q", c.name, err, set, c.want)
		}
	}
}

// A signature is matched to a key by name and key hash, so two keys may share a
// name, and one key may be listed under two names.
func TestParseKeysSameNameOrSameKey(t *testing.T) {
	a, b := exampleVKey(latamV2, "latam 2"), exampleVKey(latamV2, "latam 2, another key")
	if set, err := ParseKeys(a + "\n" + b + "\n"); err != nil || len(set.Keys()) != 2 {
		t.Errorf("two keys with one name: %v", err)
	}
	same := exampleKey("latam 2").Public().(ed25519.PublicKey)
	if set, err := ParseKeys(VKey(latamV2, same) + "\n" + VKey(latamV1, same) + "\n"); err != nil || len(set.Keys()) != 2 {
		t.Errorf("one key under two names: %v", err)
	}
}

// The notes of every key in the file verify, each by its own key, and not by another one.
func TestKeySetVerifiesWhatEachKeySigned(t *testing.T) {
	v2, v1 := exampleKey("latam 2"), exampleKey("latam 1")
	set, err := ParseKeys(VKey(latamV2, v2.Public().(ed25519.PublicKey)) + "\n" + VKey(latamV1, v1.Public().(ed25519.PublicKey)) + "\n")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 1, 14, 20, 5, 0, time.UTC)
	body := "log.example/v1\n7\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
	for _, c := range []struct {
		name   string
		signer note.Signer
		ok     bool
	}{
		{"the current key", NewSigner(latamV2, v2, func() time.Time { return at }), true},
		{"the previous key", NewSigner(latamV1, v1, func() time.Time { return at }), true},
		{"the previous name with the current key", NewSigner(latamV1, v2, func() time.Time { return at }), false},
		{"a key that is not listed", NewSigner(latamV2, exampleKey("someone else"), func() time.Time { return at }), false},
		{"another witness", NewSigner(europe1, exampleKey("europe 1"), func() time.Time { return at }), false},
	} {
		signed, err := note.Sign(&note.Note{Text: body}, c.signer)
		if err != nil {
			t.Fatal(err)
		}
		n, err := note.Open(signed, note.VerifierList(set.Verifiers()...))
		if got := err == nil && len(n.Sigs) == 1; got != c.ok {
			t.Errorf("%s: verified = %v (%v), want %v", c.name, got, err, c.ok)
		}
	}

	// The same for what a witness signs besides checkpoints, with the plain signed-note form of the keys.
	vs, err := set.NoteVerifiers()
	if err != nil || len(vs) != 2 {
		t.Fatal(vs, err)
	}
	plain := func(name string, k ed25519.PrivateKey) string {
		vkey, err := note.NewEd25519VerifierKey(name, k.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		return vkey
	}
	if got := []string{vs[0].Name(), vs[1].Name()}; !slices.Equal(got, []string{latamV2, latamV1}) {
		t.Errorf("plain verifiers %v", got)
	}
	want, err := note.NewVerifier(plain(latamV1, v1))
	if err != nil || vs[1].KeyHash() != want.KeyHash() {
		t.Errorf("the plain verifier of the previous key is not the plain key: %v", err)
	}
}

// The set it returns cannot be used to change the set.
func TestKeySetIsNotChangedFromOutside(t *testing.T) {
	set, err := ParseKeys(exampleVKey(latamV2, "latam 2") + "\n" + exampleVKey(latamV1, "latam 1"))
	if err != nil {
		t.Fatal(err)
	}
	set.Keys()[0] = nil
	set.Names()[0] = "x"
	set.Verifiers()[0] = nil
	if set.Current() == nil || set.Names()[0] != latamV2 || set.Verifiers()[0] == nil {
		t.Error("the set was changed through what it returned")
	}
}

// Whatever a key file says, it is either refused or a list of keys of one
// witness that are all different and in the order of the file.
func FuzzParseKeys(f *testing.F) {
	v2, v1 := exampleVKey(latamV2, "latam 2"), exampleVKey(latamV1, "latam 1")
	for _, s := range []string{
		v1, v1 + "\n", v2 + "\n" + v1 + "\n", "\n" + v2 + "\n\n" + v1,
		v1 + "\n" + v1, v2 + "\n" + exampleVKey(europe1, "europe 1"), "TODO", "", "\n", v2 + " " + v1,
		"#" + v1, v1 + "\r\n" + v2 + "\r\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		set, err := ParseKeys(text)
		if err != nil {
			if set != nil {
				t.Errorf("an error and a set: %v", err)
			}
			return
		}
		seen := map[nameHash]bool{}
		for i, k := range set.Keys() {
			if Family(k.Name()) != set.Family() {
				t.Errorf("key %d is %s, not of %s", i, k.Name(), set.Family())
			}
			id := nameHash{k.Name(), k.KeyHash()}
			if seen[id] {
				t.Errorf("key %d is listed twice", i)
			}
			seen[id] = true
			if _, err := NewVerifier(k.VKey()); err != nil {
				t.Errorf("key %d does not read back: %v", i, err)
			}
		}
		if len(seen) == 0 || set.Current() != set.Keys()[0] {
			t.Errorf("no keys, or the current one is not the first")
		}
	})
}
