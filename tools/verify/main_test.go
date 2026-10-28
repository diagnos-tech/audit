package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		"data/v1/cia/runs/2026/10/01/1105Z.json",
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
