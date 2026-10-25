package main

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/check"
	"github.com/diagnos-tech/audit/tools/internal/merkle"
	"github.com/diagnos-tech/audit/tools/internal/record"
	"github.com/diagnos-tech/audit/tools/internal/tiles/tilestest"
)

// verifyAll runs `verify all` over dir and returns the failing reports.
func verifyAll(t *testing.T, dir string) (failed []string, warned int) {
	t.Helper()
	src, err := record.Open(context.Background(), nil, dir)
	if err != nil {
		t.Fatal(err)
	}
	var opts check.TimestampOptions
	if _, err := exec.LookPath("openssl"); err == nil {
		opts.OpenSSL = &check.OpenSSL{Keys: src, Prefix: "keys/"}
	} else {
		t.Log("openssl not found: token signatures are not checked")
	}
	reports, err := check.All(dir, src, check.NewKeyring(src, "keys/"), opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reports {
		switch r.Worst() {
		case check.Fail:
			var buf bytes.Buffer
			r.Print(&buf, true)
			failed = append(failed, buf.String())
		case check.Warn:
			warned++
		}
	}
	return failed, warned
}

func TestExamplesVerify(t *testing.T) {
	dir := t.TempDir()
	if _, err := generate(dir); err != nil {
		t.Fatal(err)
	}
	failed, warned := verifyAll(t, dir)
	for _, f := range failed {
		t.Error(f)
	}
	if warned != 1 {
		t.Errorf("%d reports with warnings, want 1 (the hour every provider failed)", warned)
	}
}

// The committed examples must be what the generator writes today, so the
// page, the docs and the verifier are always shown consistent data.
func TestCommittedExamplesAreCurrent(t *testing.T) {
	dir := t.TempDir()
	if _, err := generate(dir); err != nil {
		t.Fatal(err)
	}
	committed := filepath.Join("..", "..", "examples")
	want := listFiles(t, dir)
	got := listFiles(t, committed)
	for path, data := range want {
		if !bytes.Equal(got[path], data) {
			t.Errorf("examples/%s is stale or missing; run `go run ./tools/genexamples`", path)
		}
		delete(got, path)
	}
	for path := range got {
		t.Errorf("examples/%s is not generated any more; run `go run ./tools/genexamples`", path)
	}
}

func listFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	for _, sub := range []string{"data", "keys"} {
		err := filepath.WalkDir(filepath.Join(root, sub), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			files[filepath.ToSlash(rel)], err = os.ReadFile(p)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

// Each kind of tampering a reader might worry about is caught.
func TestTamperingIsCaught(t *testing.T) {
	for _, c := range []struct {
		name   string
		tamper func(dir string) error
		expect string // a substring of the failure
	}{
		{"proof node changed", func(dir string) error {
			return edit(dir, "data/v1/audit/witness/2026/09/30/120002Z.json", `"consistency": [
    "`, `"consistency": [
    "A`, 1)
		}, "consistency"},
		{"witness record deleted", func(dir string) error {
			return os.Remove(filepath.Join(dir, "data/v1/audit/witness/2026/09/30/120002Z.json"))
		}, "does not exist"},
		{"subject edited", func(dir string) error {
			return edit(dir, "data/v1/timestamps/2026/09/30/12Z.json", `"size": `, `"size": 1`, 1)
		}, "imprint"},
		{"past hour rewritten", func(dir string) error {
			return edit(dir, "data/v1/timestamps/2026/09/30/12Z.json", `"checks": [`, `"checks": [ `, 1)
		}, "chain"},
		{"stray file", func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "data/v1/leaves.json"), []byte("{}"), 0o644)
		}, "no place"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := generate(dir); err != nil {
				t.Fatal(err)
			}
			if err := c.tamper(dir); err != nil {
				t.Fatal(err)
			}
			failed, _ := verifyAll(t, dir)
			if !strings.Contains(strings.Join(failed, "\n"), c.expect) {
				t.Errorf("tampering not reported as %q; failures:\n%s", c.expect, strings.Join(failed, "\n"))
			}
		})
	}
}

func edit(dir, path, old, new string, n int) error {
	full := filepath.Join(dir, path)
	b, err := os.ReadFile(full)
	if err != nil {
		return err
	}
	if !bytes.Contains(b, []byte(old)) {
		return os.ErrNotExist
	}
	return os.WriteFile(full, bytes.Replace(b, []byte(old), []byte(new), n), 0o644)
}

// `verify consistency` against the example logs served over HTTP: an honest
// log passes, a log that rewrote history after the witness saw it fails.
func TestConsistencyFromLog(t *testing.T) {
	dir := t.TempDir()
	s, err := generate(dir)
	if err != nil {
		t.Fatal(err)
	}
	audit := s.logs[0]
	src, _ := record.Open(context.Background(), nil, dir)
	keys := check.NewKeyring(src, "keys/")
	first := "data/v1/audit/witness/2026/09/30/110005Z.json"

	serve := func(t *testing.T, tree *merkle.Tree) string {
		root, _ := merkle.Root(tree.Size(), tree)
		cp, err := s.checkpoint(audit, tree.Size(), root)
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(&tilestest.Log{Tree: tree, Checkpoint: cp})
		t.Cleanup(srv.Close)
		return srv.URL + "/audit/v1/"
	}

	t.Run("honest", func(t *testing.T) {
		// The log keeps growing after the last witness run.
		grown := &audit.tree
		for i := range 300 {
			grown.AppendLeaf(fmt.Appendf(nil, "later %d", i))
		}
		url := serve(t, grown)
		for _, args := range [][2]string{{first, ""}, {first, audit.last.path}} {
			r := check.FromLog(context.Background(), http.DefaultClient, src, keys, args[0], args[1], url)
			var buf bytes.Buffer
			r.Print(&buf, false)
			if r.Failed() {
				t.Error(buf.String())
			}
			t.Log("\n" + buf.String())
		}
	})

	t.Run("rewritten", func(t *testing.T) {
		// Same size as the honest log, but one early entry was replaced.
		fork := &merkle.Tree{}
		for i := range audit.tree.Size() {
			h, _ := audit.tree.Node(0, i)
			if i == 182_400 {
				h = merkle.HashLeaf([]byte("rewritten"))
			}
			fork.AppendHash(h)
		}
		r := check.FromLog(context.Background(), http.DefaultClient, src, keys, first, audit.last.path, serve(t, fork))
		if !r.Failed() {
			t.Error("a log that rewrote a witnessed entry passed")
		}
	})
}
