package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/cosig"
)

func exec(args ...string) (code int, out, errOut string) {
	var o, e bytes.Buffer
	code = run(context.Background(), args, &o, &e)
	return code, o.String(), e.String()
}

func TestIncidentsCommand(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good, err := os.ReadFile(filepath.Join("..", "..", "incidents", "2026-10-27-example.md"))
	if err != nil {
		t.Fatal(err)
	}
	ok := write("2026-10-27-example.md", string(good))
	readme := write("README.md", "# not an incident\n")
	bad := write("2026-10-28-broken.md", strings.Replace(string(good), "id: 2026-10-27-example", "id: other", 1))

	code, out, _ := exec("incidents", ok, readme)
	if code != 0 || !strings.Contains(out, "not published") || !strings.Contains(out, "ignored") {
		t.Errorf("valid files: exit %d\n%s", code, out)
	}
	code, out, _ = exec("incidents", ok, bad)
	if code != 1 || !strings.Contains(out, "must equal the file name") {
		t.Errorf("a broken file must fail: exit %d\n%s", code, out)
	}
	if code, _, _ := exec("incidents"); code != 2 {
		t.Errorf("no files: exit %d, want 2", code)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{}, {"nope"}, {"release"}, {"release", "-cosign"}, {"cia", "-root", "https://example.invalid/"}, {"all", "-root", "https://example.invalid/"},
		{"witness"}, {"incidents", "-bogus"},
	} {
		if code, _, _ := exec(args...); code != 2 {
			t.Errorf("verify %v: exit %d, want 2", args, code)
		}
	}
}

func TestCIAOnAnEmptyRepository(t *testing.T) {
	dir := t.TempDir()
	code, out, _ := exec("cia", "-root", dir)
	if code != 0 || !strings.Contains(out, "nothing to check") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

// The commands the data workflow runs on the files a commit changed.
func TestCIACommandAcceptsEveryKindOfCIAFile(t *testing.T) {
	root := filepath.Join("..", "..", "examples")
	vault, err := filepath.Glob(filepath.Join(root, "data/v1/cia/releases/vault/*"))
	if err != nil || len(vault) != 1 {
		t.Fatalf("%v %v", vault, err)
	}
	release := "data/v1/cia/releases/vault/" + filepath.Base(vault[0])
	for _, file := range []string{
		"data/v1/cia/runs/2026/09/30/1925Z.json", // cia-run/v1
		"data/v1/cia/runs/2026/10/01/1105Z.json", // cia-run/v2, both witnesses
		"data/v1/cia/runs/2026/10/01/1135Z.json", // cia-run/v2, the secondary silent
		"data/v1/cia/runs/2026/10/01/1405Z.json", // cia-run/v2, a regional failure
		"data/v1/cia/incidents/2026/10/01/0935Z.json",
		"data/v1/cia/days/2026/10/01.json",
		"data/v1/cia/summary.json",
		"data/v1/cia/latest.json",
		"data/v1/cia/incidents.json",
		"data/v1/cia/changes.json",
		"data/v1/cia/changes-recent.json",
		"data/v1/cia/incidents/events/2026/10/01/2026-10-01-auto-vault-a-0310-1.json",
		"data/v1/cia/incidents/events/2026/10/01/2026-10-01-auto-status-i-1335-2.json",
		"data/v1/cia/runs/2026/10/01/0900Z.json",
		"data/v1/sync.json",
		release + "/verdict.json",
		release + "/manifest.json",
	} {
		code, out, errOut := exec("cia", "-q", "-root", root, file)
		if code != 0 || strings.Contains(out, "FAIL") { // warnings (no Sigstore bundle in the examples) are fine
			t.Errorf("verify cia -q %s: exit %d\n%s%s", file, code, out, errOut)
		}
	}
	if code, out, _ := exec("cia", "-q", "-root", root, "data/v1/cia/runs/2026/10/01/1105Z.json", "data/v1/cia/nothing.json"); code != 1 || !strings.Contains(out, "does not exist") {
		t.Errorf("a named file that is not there must fail: exit %d\n%s", code, out)
	}
}

// A witness record and a finding of the second witness are verified by the same
// commands, from their own namespace, with the key keys/witness/latam.vkey.
func TestWitnessCommandsFollowTheNamespace(t *testing.T) {
	root := filepath.Join("..", "..", "examples")
	for _, c := range [][]string{
		{"witness", "-q", "-root", root, "data/v1/witnesses/latam/audit/witness/2026/10/01/102507Z.json"},
		{"witness", "-q", "-root", root, "data/v1/audit/witness/2026/10/01/102507Z.json"},
	} {
		if code, out, errOut := exec(c...); code != 0 {
			t.Errorf("verify %v: exit %d\n%s%s", c[:1], code, out, errOut)
		}
	}
	// Pin a keys directory that does not have the second witness's key yet: its records verify, with a warning.
	keys := t.TempDir()
	if err := os.MkdirAll(filepath.Join(keys, "witness"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"witness/auditor.vkey", "logs/audit.vkey", "logs/signs.vkey"} {
		data, err := os.ReadFile(filepath.Join(root, "keys", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(keys, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keys, f), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	code, out, _ := exec("witness", "-root", root, "-keys", keys, "data/v1/witnesses/latam/audit/witness/2026/10/01/102507Z.json")
	if code != 0 || !strings.Contains(out, "is not published yet") || !strings.Contains(out, "with warnings") {
		t.Errorf("an absent key: exit %d\n%s", code, out)
	}
	code, out, _ = exec("cia", "-q", "-root", root, "-keys", keys, "data/v1/cia/runs/2026/10/01/1105Z.json")
	if code != 0 || !strings.Contains(out, "is not published yet") {
		t.Errorf("an absent key on a run record: exit %d\n%s", code, out)
	}
}

// A pinned keys directory whose witness file lists a new key first and the key
// the records were signed with after it: the records still verify, from either
// namespace and in a run record. Without the old key, or with the other
// witness's key in the file, they do not.
func TestPinnedKeysDirectoryAfterARotation(t *testing.T) {
	root := filepath.Join("..", "..", "examples")
	keysWith := func(latam string) string {
		dir := t.TempDir()
		for _, f := range []string{"witness/auditor.vkey", "logs/audit.vkey", "logs/signs.vkey"} {
			data, err := os.ReadFile(filepath.Join(root, "keys", f))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, f)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, f), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "witness/latam.vkey"), []byte(latam), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	read := func(f string) string {
		data, err := os.ReadFile(filepath.Join(root, "keys", f))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	next := cosig.VKey("witness.example/latam/v2", pub)
	previous, europe := read("witness/latam.vkey"), read("witness/auditor.vkey")

	record := "data/v1/witnesses/latam/audit/witness/2026/10/01/102507Z.json"
	run := "data/v1/cia/runs/2026/10/01/1105Z.json"
	for _, c := range []struct {
		name     string
		file     string
		code     int
		contains string
		alsoRun  bool // check the run record too: its note is signed with the same key
	}{
		{"the file as it was", previous, 0, "OK", true},
		{"the new key first, the old one after it", next + "\n" + previous, 0, "OK", true},
		{"blank lines between them", "\n" + next + "\n\n" + previous + "\n\n", 0, "OK", false},
		{"the old key dropped", next + "\n", 1, "witness.example/latam/v2", true},
		{"the other witness's key listed", next + "\n" + previous + europe, 1, "is not a key of witness.example/latam", false},
		{"the old key twice", next + "\n" + previous + previous, 1, "is already listed on line 2", false},
		{"a line that is not a key", next + "\n" + previous + "pending\n", 1, "line 3: cosig: malformed witness vkey", false},
	} {
		dir := keysWith(c.file)
		cmds := [][]string{{"witness", "-q", "-root", root, "-keys", dir, record}}
		if c.alsoRun {
			cmds = append(cmds, []string{"cia", "-q", "-root", root, "-keys", dir, run})
		}
		for _, args := range cmds {
			code, out, errOut := exec(args...)
			if code != c.code || !strings.Contains(out, c.contains) {
				t.Errorf("%s: verify %s: exit %d, want %d with %q\n%s%s", c.name, args[0], code, c.code, c.contains, out, errOut)
			}
		}
	}
}

func TestReleaseCommandAcceptsQuietAndCosign(t *testing.T) {
	root := filepath.Join("..", "..", "examples")
	vault, _ := filepath.Glob(filepath.Join(root, "data/v1/cia/releases/vault/*"))
	if len(vault) != 1 {
		t.Fatal(vault)
	}
	dir := "data/v1/cia/releases/vault/" + filepath.Base(vault[0])
	if code, out, _ := exec("release", "-q", "-root", root, dir); code != 0 {
		t.Errorf("verify release -q: exit %d\n%s", code, out)
	}
	// The examples archive no bundle, so cosign has nothing to check: a failure, not a usage error.
	code, out, _ := exec("release", "-cosign", "-q", "-root", root, dir)
	if code != 1 || !strings.Contains(out, "not archived") {
		t.Errorf("verify release -cosign -q: exit %d\n%s", code, out)
	}
}

// A web server cannot be walked, so the commands that list files say how to
// get a clone.
func TestListingOverHTTPNeedsAClone(t *testing.T) {
	for _, cmd := range []string{"cia", "all"} {
		code, _, errOut := exec(cmd, "-root", "https://raw.githubusercontent.com/diagnos-tech/audit/develop/")
		if code != 2 || !strings.Contains(errOut, "listing files needs a clone of the repository: git clone https://github.com/diagnos-tech/audit") {
			t.Errorf("verify %s: exit %d\n%s", cmd, code, errOut)
		}
	}
}
