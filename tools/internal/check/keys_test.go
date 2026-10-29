package check

import (
	"slices"
	"strings"
	"testing"
)

// A witness's key file is its current key and, after a rotation, the keys it
// replaced, one per line. The keyring refuses a file that lists a key of another
// witness, a key twice or something that is not a key, whichever witness it is.
func TestWitnessKeyFile(t *testing.T) {
	v1 := newTestKey(t, "witness.example/latam/v1", "latam 1")
	v2 := newTestKey(t, "witness.example/latam/v2", "latam 2")
	europe := newTestKey(t, "witness.example/auditor/v1", "europe 1")
	for _, c := range []struct {
		name    string
		witness string
		file    string
		want    []string // names, current first
		wantErr string
	}{
		{"one key, as before", "latam", v1.vkey + "\n", []string{v1.name}, ""},
		{"one key without a newline", "latam", v1.vkey, []string{v1.name}, ""},
		{"the current key and the previous one", "latam", keyFile(v2, v1), []string{v2.name, v1.name}, ""},
		{"blank lines are ignored", "latam", "\n" + v2.vkey + "\n\n" + v1.vkey + "\n\n", []string{v2.name, v1.name}, ""},
		{"the primary witness rotates too", "europe", keyFile(newTestKey(t, "witness.example/auditor/v2", "europe 2"), europe), []string{"witness.example/auditor/v2", europe.name}, ""},

		{"a key of another witness listed by mistake", "latam", keyFile(v2, europe), nil, "is not a key of witness.example/latam"},
		{"the other witness's key first", "latam", keyFile(europe, v2), nil, "is not a key of witness.example/auditor"},
		{"the primary's file lists a key of the second witness", "europe", keyFile(europe, v1), nil, "is not a key of witness.example/auditor"},
		{"a key listed twice", "latam", keyFile(v2, v1, v1), nil, "is already listed on line 2"},
		{"a malformed line", "latam", v2.vkey + "\nTODO\n", nil, "line 2: cosig: malformed witness vkey"},
		{"a line with a key hash that does not match", "latam", v2.vkey + "\n" + strings.Replace(v1.vkey, "+", "+00", 1) + "\n", nil, "line 2: cosig: malformed"},
		{"two keys on a line", "latam", v2.vkey + " " + v1.vkey + "\n", nil, "malformed witness vkey"},
		{"a file that is not a key", "latam", "TODO\n", nil, "malformed witness vkey"},
		{"an empty file", "latam", "\n", nil, "has no key"},
	} {
		set, err := keysWithFile(c.witness, c.file).WitnessKeys(c.witness, "")
		switch {
		case c.wantErr != "":
			if err == nil || !strings.Contains(err.Error(), c.wantErr) || !strings.Contains(err.Error(), "keys/"+WitnessKeyFileOf(c.witness)) {
				t.Errorf("%s: err = %v, want one with %q that names the file", c.name, err, c.wantErr)
			}
		case err != nil:
			t.Errorf("%s: %v", c.name, err)
		case !slices.Equal(set.Names(), c.want):
			t.Errorf("%s: keys %v, want %v", c.name, set.Names(), c.want)
		}
	}
}

// A file that is wrong is a failure for the witness whose key may be missing too.
func TestOptionalWitnessKeysRefuseABadFile(t *testing.T) {
	v2 := newTestKey(t, "witness.example/latam/v2", "latam 2")
	europe := newTestKey(t, "witness.example/auditor/v1", "europe 1")
	_, absent, err := keysWithFile("latam", keyFile(v2, europe)).OptionalWitnessKeys("latam", "")
	if absent || err == nil {
		t.Errorf("absent = %v, err = %v: a file with another witness's key was accepted or ignored", absent, err)
	}
	if _, absent, err := keysWithFile("europe", keyFile(v2)).OptionalWitnessKeys("latam", ""); !absent || err != nil {
		t.Errorf("absent = %v, err = %v: a missing file is not a failure for the second witness", absent, err)
	}
}

// A record names the key that signed it; the file must list a key of that name,
// which after a rotation can be a previous one.
func TestWitnessKeysAreMatchedByTheNameOfTheRecord(t *testing.T) {
	v1 := newTestKey(t, "witness.example/latam/v1", "latam 1")
	v2 := newTestKey(t, "witness.example/latam/v2", "latam 2")
	for _, c := range []struct {
		name    string
		file    string
		record  string
		wantErr string
	}{
		{"the current key", keyFile(v2, v1), v2.name, ""},
		{"a previous key", keyFile(v2, v1), v1.name, ""},
		{"no name asked for", keyFile(v2, v1), "", ""},
		{"a name the file does not list", keyFile(v2, v1), "witness.example/latam/v3", `the witness keys are named "witness.example/latam/v2", "witness.example/latam/v1", but the record says "witness.example/latam/v3"`},
		{"a previous key that was removed from the file", keyFile(v2), v1.name, `the witness key is named "witness.example/latam/v2", but the record says "witness.example/latam/v1"`},
		{"another witness's name", keyFile(v2, v1), "witness.example/auditor/v1", "but the record says"},
	} {
		_, err := keysWithFile("latam", c.file).WitnessKeys("latam", c.record)
		if (err == nil) != (c.wantErr == "") || err != nil && !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.wantErr)
		}
	}
}
