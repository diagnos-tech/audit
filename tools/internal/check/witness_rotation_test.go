package check

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/diagnos-tech/audit/tools/internal/cosig"
	"github.com/diagnos-tech/audit/tools/internal/merkle"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// A record that a witness signed before it rotated its key, and one it signed
// after, in one chain. The keys are made when the test runs.
type rotationFixture struct {
	t       *testing.T
	wid     string
	log     testKey
	logNote note.Verifier
	tree    merkle.Tree
	src     memSource
	last    *record.Witness
	lastAt  string
}

const rotationLog = "audit"

func newRotationFixture(t *testing.T, wid string) *rotationFixture {
	t.Helper()
	log := newTestKey(t, "log.example/audit", "rotation log")
	v, err := note.NewVerifier(log.plain)
	if err != nil {
		t.Fatal(err)
	}
	return &rotationFixture{t: t, wid: wid, log: log, logNote: v, src: memSource{"keys/logs/audit.vkey": []byte(log.plain + "\n")}}
}

// checkpoint is the checkpoint of the tree at size, signed by the log.
func (f *rotationFixture) checkpoint(size uint64, tree *merkle.Tree) []byte {
	f.t.Helper()
	root, err := merkle.Root(size, tree)
	if err != nil {
		f.t.Fatal(err)
	}
	body := fmt.Sprintf("log.example/audit\n%d\n%s\n", size, b64(root[:]))
	signed, err := note.Sign(&note.Note{Text: body}, f.log.signer)
	if err != nil {
		f.t.Fatal(err)
	}
	return signed
}

// witnessed adds a record that the log grew by n entries and that every one of
// signers cosigned at the time at, naming the key named in it, and returns its path.
func (f *rotationFixture) witnessed(at time.Time, grow int, named testKey, signers ...testKey) string {
	f.t.Helper()
	for range grow {
		f.tree.AppendLeaf([]byte(fmt.Sprintf("entry %d", f.tree.Size())))
	}
	size := f.tree.Size()
	n, err := note.Open(f.checkpoint(size, &f.tree), note.VerifierList(f.logNote))
	if err != nil {
		f.t.Fatal(err)
	}
	var cosigners []note.Signer
	for _, k := range signers {
		cosigners = append(cosigners, k.cosigner(at))
	}
	signed, err := note.Sign(n, cosigners...)
	if err != nil {
		f.t.Fatal(err)
	}
	root, _ := merkle.Root(size, &f.tree)
	keyHash, err := vkeyHash(named)
	if err != nil {
		f.t.Fatal(err)
	}
	rec := record.Witness{
		Schema: "witness/v1", Log: rotationLog, Origin: "log.example/audit", URL: "https://log.example/audit/",
		WitnessedAt: record.FormatTime(at),
		Checkpoint:  record.Checkpoint{Size: size, Root: b64(root[:]), Note: string(signed)},
		Cosignature: record.Cosignature{Name: named.name, KeyHash: keyHash},
		Consistency: []string{},
	}
	path := record.WitnessPathOf(f.wid, rotationLog, at)
	if f.last != nil {
		rec.Previous = &record.Previous{Size: f.last.Checkpoint.Size, Root: f.last.Checkpoint.Root, Record: f.lastAt}
		proof, err := merkle.ConsistencyProof(f.last.Checkpoint.Size, size, &f.tree)
		if err != nil {
			f.t.Fatal(err)
		}
		for _, h := range proof {
			rec.Consistency = append(rec.Consistency, b64(h[:]))
		}
	}
	f.put(path, rec)
	f.last, f.lastAt = &rec, path
	return path
}

func (f *rotationFixture) put(path string, v any) {
	f.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		f.t.Fatal(err)
	}
	f.src[path] = data
}

// repo is the repository with the witness's key file holding text, and a keyring over it.
func (f *rotationFixture) repo(text string) (memSource, *Keyring) {
	src := memSource{}
	for k, v := range f.src {
		src[k] = v
	}
	src["keys/"+WitnessKeyFileOf(f.wid)] = []byte(text)
	return src, NewKeyring(src, "keys/")
}

// vkeyHash is the key hash a vkey states, the eight hex digits a record writes.
func vkeyHash(k testKey) (string, error) {
	v, err := cosig.NewVerifier(k.vkey)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08x", v.KeyHash()), nil
}

// reportOf is the worst result of a report and the report as it prints.
func reportOf(r *Report) (Status, string) {
	var out strings.Builder
	r.Print(&out, false)
	return r.Worst(), out.String()
}

// The point of the key file: after a witness rotates its key, the records it
// signed before still verify, and so do the ones it signs now.
func TestWitnessRecordsAcrossAKeyRotation(t *testing.T) {
	for _, wid := range []string{"latam", "europe"} {
		t.Run(wid, func(t *testing.T) {
			family := "witness.example/" + map[string]string{"latam": "latam", "europe": "auditor"}[wid]
			v1 := newTestKey(t, family+"/v1", wid+" 1")
			v2 := newTestKey(t, family+"/v2", wid+" 2")
			f := newRotationFixture(t, wid)
			before := time.Date(2026, 10, 1, 9, 0, 5, 0, time.UTC)
			after := time.Date(2026, 10, 1, 15, 0, 5, 0, time.UTC)
			old := f.witnessed(before, 10, v1, v1)
			current := f.witnessed(after, 5, v2, v2)

			for _, c := range []struct {
				name     string
				file     string
				path     string
				worst    Status
				contains string
			}{
				{"an old record, with the file as it was before the rotation", v1.vkey + "\n", old, OK, family + "/v1 at 2026-10-01T09:00:05Z"},
				{"an old record, the previous key still listed", keyFile(v2, v1), old, OK, family + "/v1 at 2026-10-01T09:00:05Z"},
				{"a new record, the previous key still listed", keyFile(v2, v1), current, OK, family + "/v2 at 2026-10-01T15:00:05Z"},
				{"the chain crosses the rotation: the new record checks its link to the old one", keyFile(v2, v1), current, OK, "consistency"},
				{"a new record, with the file as it was before the rotation", v1.vkey + "\n", current, Fail, "the record says " + `"` + family + `/v2"`},
				{"an old record after the previous key was dropped from the file", v2.vkey + "\n", old, Fail, "the record says " + `"` + family + `/v1"`},
			} {
				src, keys := f.repo(c.file)
				_, r := Witness(src, keys, c.path)
				if w, text := reportOf(r); w != c.worst || !strings.Contains(text, c.contains) {
					t.Errorf("%s: worst %v, want %v containing %q:\n%s", c.name, w, c.worst, c.contains, text)
				}
			}
		})
	}
}

// What the note is signed by and what the record says must agree, and a key
// that is not listed does not count, whatever else is listed.
func TestWitnessRecordsAndTheKeysThatSignedThem(t *testing.T) {
	v1 := newTestKey(t, "witness.example/latam/v1", "latam 1")
	v2 := newTestKey(t, "witness.example/latam/v2", "latam 2")
	v0 := newTestKey(t, "witness.example/latam/v0", "latam 0")
	elsewhere := newTestKey(t, "witness.example/auditor/v1", "europe 1")
	impostor := newTestKey(t, "witness.example/latam/v2", "latam 2, someone else")
	at := time.Date(2026, 10, 1, 15, 0, 5, 0, time.UTC)

	for _, c := range []struct {
		name     string
		named    testKey
		signers  []testKey
		file     string
		worst    Status
		contains string
	}{
		// While it rotates a witness may sign with both keys: the record names the one that counts.
		{"cosigned by both, the record names the current one", v2, []testKey{v1, v2}, keyFile(v2, v1), OK, "cosignature    witness.example/latam/v2 at"},
		{"cosigned by both, the record names the previous one", v1, []testKey{v1, v2}, keyFile(v2, v1), OK, "cosignature    witness.example/latam/v1 at"},
		{"cosigned by both, only the previous one is listed", v1, []testKey{v1, v2}, v1.vkey + "\n", OK, "cosignature    witness.example/latam/v1 at"},

		{"the record names the current key, the note carries the previous one's", v2, []testKey{v1}, keyFile(v2, v1), Fail, "signed by witness.example/latam/v1, but the record says witness.example/latam/v2"},
		{"the record names a key hash that signed nothing", impostorNamed(t, v2, impostor), []testKey{v2}, keyFile(v2, v1), Fail, "key hash is"},

		{"signed by a key of another witness", v1, []testKey{elsewhere}, keyFile(v2, v1), Fail, "no valid signature by any of witness.example/latam/v2, witness.example/latam/v1"},
		{"signed by a key of the family that the file does not list", v2, []testKey{v0}, keyFile(v2, v1), Fail, "witness.example/latam/v0 (key hash"},
		{"signed by another key with the name of a listed one", v2, []testKey{impostor}, keyFile(v2, v1), Fail, "which the key file does not list"},
		{"a previous key removed from the file says so", v1, []testKey{v1}, v2.vkey + "\n", Fail, "the record says"},

		// A key of another witness in the file is refused before any signature is looked at.
		{"a key of another witness listed by mistake", v1, []testKey{v1}, keyFile(v2, v1, elsewhere), Fail, "line 3: key \"witness.example/auditor/v1\" is not a key of witness.example/latam"},
		{"the same key listed twice", v1, []testKey{v1}, keyFile(v2, v1, v1), Fail, "is already listed on line 2"},
		{"a malformed line", v1, []testKey{v1}, v2.vkey + "\nTODO\n" + v1.vkey + "\n", Fail, "line 2: cosig: malformed witness vkey"},
	} {
		f := newRotationFixture(t, "latam")
		path := f.witnessed(at, 10, c.named, c.signers...)
		src, keys := f.repo(c.file)
		_, r := Witness(src, keys, path)
		if w, text := reportOf(r); w != c.worst || !strings.Contains(text, c.contains) {
			t.Errorf("%s: worst %v, want %v containing %q:\n%s", c.name, w, c.worst, c.contains, text)
		}
	}
}

// impostorNamed is the key v, but with the key hash of another key of the same name.
func impostorNamed(t *testing.T, v, other testKey) testKey {
	t.Helper()
	out := v
	out.vkey = other.vkey
	return out
}

// A finding is evidence the witness cosigned the checkpoint it names; that
// holds for a cosignature by a key the witness has since replaced.
func TestFindingsAcrossAKeyRotation(t *testing.T) {
	v1 := newTestKey(t, "witness.example/latam/v1", "latam 1")
	v2 := newTestKey(t, "witness.example/latam/v2", "latam 2")
	elsewhere := newTestKey(t, "witness.example/auditor/v1", "europe 1")
	at := time.Date(2026, 10, 1, 9, 0, 5, 0, time.UTC)

	build := func(cosigner testKey) (*rotationFixture, string) {
		f := newRotationFixture(t, "latam")
		witnessed := f.witnessed(at, 10, cosigner, cosigner)
		// The log shows another tree for the same size, signed by the log: a fork.
		var fork merkle.Tree
		for i := range f.tree.Size() - 1 {
			h, _ := f.tree.Node(0, i)
			fork.AppendHash(h)
		}
		fork.AppendLeaf([]byte("a different last entry"))
		size := f.tree.Size()
		observed := f.checkpoint(size, &fork)
		forkRoot, _ := merkle.Root(size, &fork)
		detected := at.Add(time.Hour)
		found := record.Finding{
			Schema: "finding/v1", Log: rotationLog, Origin: "log.example/audit", DetectedAt: record.FormatTime(detected), Kind: "equivocation",
			Summary:     "The log signed two different roots for one size.",
			Witnessed:   record.Evidence{Size: size, Root: f.last.Checkpoint.Root, Note: f.last.Checkpoint.Note, Record: witnessed},
			Observed:    record.Evidence{Size: size, Root: b64(forkRoot[:]), Note: string(observed)},
			Consistency: []string{},
		}
		path := record.FindingPathOf("latam", rotationLog, detected)
		f.put(path, found)
		return f, path
	}

	for _, c := range []struct {
		name     string
		cosigner testKey
		file     string
		worst    Status
		contains string
	}{
		{"cosigned by the key the file lists first", v2, keyFile(v2, v1), OK, "two roots signed by the log"},
		{"cosigned by a key that was replaced", v1, keyFile(v2, v1), OK, "signed by 2 required key(s)"},
		{"cosigned by a key that was replaced, with the file as it was before", v1, v1.vkey + "\n", OK, "signed by 2 required key(s)"},
		{"cosigned by a key that is no longer listed", v1, v2.vkey + "\n", Fail, "the record says"},
		{"a key of another witness in the file", v1, keyFile(v2, v1, elsewhere), Fail, "is not a key of witness.example/latam"},
	} {
		f, path := build(c.cosigner)
		src, keys := f.repo(c.file)
		_, r := Finding(src, keys, path)
		if w, text := reportOf(r); w != c.worst || !strings.Contains(text, c.contains) {
			t.Errorf("%s: worst %v, want %v containing %q:\n%s", c.name, w, c.worst, c.contains, text)
		}
	}
}

// A measurement note is signed with the plain form of the witness's key. The
// notes of the runs before a rotation verify with the previous key and the notes
// after it with the current one; a key of another witness verifies neither.
func TestMeasurementNotesAcrossAKeyRotation(t *testing.T) {
	v1 := newTestKey(t, "witness.example/latam/v1", "latam 1")
	v2 := newTestKey(t, "witness.example/latam/v2", "latam 2")
	europe1 := newTestKey(t, "witness.example/auditor/v1", "europe 1")
	europe2 := newTestKey(t, "witness.example/auditor/v2", "europe 2")
	stranger := newTestKey(t, "witness.example/latam/v1", "latam 1, someone else")
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
		signer    testKey
		wantWorst Status
		contains  string
	}{
		{"before the rotation, the file as it was", "latam", keysWith(map[string]testKey{"latam": v1}), v1, OK, "signed by witness.example/latam/v1;"},
		{"a note signed by the previous key", "latam", keysWithFile("latam", keyFile(v2, v1)), v1, OK, "signed by witness.example/latam/v1;"},
		{"a note signed by the current key", "latam", keysWithFile("latam", keyFile(v2, v1)), v2, OK, "signed by witness.example/latam/v2;"},
		{"the primary witness, the previous key", "europe", keysWithFile("europe", keyFile(europe2, europe1)), europe1, OK, "signed by witness.example/auditor/v1;"},
		{"the primary witness, the current key", "europe", keysWithFile("europe", keyFile(europe2, europe1)), europe2, OK, "signed by witness.example/auditor/v2;"},

		{"a note signed by the previous key, which was dropped from the file", "latam", keysWithFile("latam", keyFile(v2)), v1, Fail, "does not verify with witness.example/latam/v2"},
		{"a note signed by a key of the same name that is not listed", "latam", keysWithFile("latam", keyFile(v2, v1)), stranger, Fail, "does not verify with any of witness.example/latam/v2, witness.example/latam/v1"},
		{"the other witness's current key", "latam", keysWithFile("latam", keyFile(v2, v1)), europe2, Fail, "does not verify"},
		{"the other witness's previous key", "latam", keysWithFile("latam", keyFile(v2, v1)), europe1, Fail, "does not verify"},
		{"a key of another witness listed by mistake", "latam", keysWithFile("latam", keyFile(v2, v1, europe1)), v1, Fail, "is not a key of witness.example/latam"},
		{"the same key listed twice", "latam", keysWithFile("latam", keyFile(v2, v1, v1)), v1, Fail, "is already listed"},
		{"a malformed line", "latam", keysWithFile("latam", keyFile(v2)+"TODO\n"), v2, Fail, "line 2: cosig: malformed witness vkey"},
	} {
		text := signNote(t, c.signer, c.id, testSlot, map[string]string{"latam": request, "europe": "none"}[c.id], digest)
		r := &Report{Subject: "run"}
		checkMeasurementNote(c.keys, c.id, entry(text), testSlot, r)
		if w, out := reportOf(r); w != c.wantWorst || !strings.Contains(out, c.contains) {
			t.Errorf("%s: worst %v, want %v containing %q:\n%s", c.name, w, c.wantWorst, c.contains, out)
		}
	}
}
