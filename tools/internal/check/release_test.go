package check

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

const releaseCommit = "3f1c9e2a7b4d6e8f0a1b2c3d4e5f60718293a4b5"

var releasePin = record.Signer{
	Issuer: "https://token.actions.githubusercontent.com", Repository: "https://github.com/example/monorepo",
	RepositoryID: "111", OwnerID: "222", Workflow: ".github/workflows/pipeline.yml", Ref: "refs/heads/main",
}

// releaseDir writes a consistent release into a fresh root and returns the
// root and the release directory (repository relative).
func releaseDir(t *testing.T, bundles bool) (string, string) {
	t.Helper()
	root := t.TempDir()
	served := "/favicon.svg"
	m := record.ReleaseManifest{Schema: "release-manifest/v1", Service: "vault", Version: "0.1.29", Commit: releaseCommit,
		Repository: releasePin.Repository, BuiltAt: "2026-10-27T09:12:44Z", Files: []record.ReleaseFile{
			{Path: "assets/favicon.svg", SHA256: strings.Repeat("a", 64), Bytes: 912, Served: &served},
			{Path: "worker/index.js", SHA256: strings.Repeat("b", 64), Bytes: 1000},
		}}
	manifest, err := record.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	digest := sum(manifest)
	dir := record.ReleaseDir("vault", digest)
	manifestPath := dir + "/manifest.json"
	v := record.CIARelease{Schema: "cia-release/v1", Service: "vault", Digest: digest, CheckedAt: "2026-10-27T09:31:07Z",
		Result: "pass", Code: "verified", Reason: "ok",
		Claim:    record.ReleaseClaim{URL: "https://vault.example/healthz", Version: "0.1.29", Commit: releaseCommit},
		Manifest: &record.ReleaseSummary{Version: "0.1.29", Commit: releaseCommit, Files: 2, Bytes: 1912, Served: 1},
		Signer: &record.ReleaseSigner{Issuer: releasePin.Issuer, SAN: releasePin.Repository + "/" + releasePin.Workflow + "@" + releasePin.Ref,
			Repository: releasePin.Repository, RepositoryID: "111", OwnerID: "222", Ref: releasePin.Ref, Commit: releaseCommit,
			Trigger: "push", Runner: "github-hosted"},
		Files:    record.ReleaseFiles{Manifest: &manifestPath},
		Verifier: record.ReleaseVerifier{Name: "sigstore-go", Version: "v1.3.0"},
	}
	files := map[string][]byte{manifestPath: manifest}
	if bundles {
		sig, prov := dir+"/manifest.json.sig", dir+"/provenance.sigstore.json"
		v.Files.Signature, v.Files.Provenance = &sig, &prov
		files[sig], files[prov] = []byte("{}"), []byte("{}")
	}
	verdict, _ := record.Encode(v)
	signers, _ := record.Encode(record.Signers{Schema: "signers/v1", Services: map[string]record.Signer{"vault": releasePin}})
	files[dir+"/verdict.json"], files[record.SignersPath] = verdict, signers
	for p, data := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, dir
}

func checkRelease(t *testing.T, root, dir string, opts ReleaseOptions) *Report {
	t.Helper()
	src, err := record.Open(context.Background(), nil, root)
	if err != nil {
		t.Fatal(err)
	}
	return Release(src, dir, opts)
}

func resultText(r *Report) string {
	var b strings.Builder
	r.Print(&b, false)
	return b.String()
}

func TestReleasePasses(t *testing.T) {
	root, dir := releaseDir(t, true)
	if r := checkRelease(t, root, dir, ReleaseOptions{}); r.Worst() != OK {
		t.Errorf("a consistent release failed:\n%s", resultText(r))
	}
	root, dir = releaseDir(t, false)
	if r := checkRelease(t, root, dir, ReleaseOptions{}); r.Worst() != Warn {
		t.Errorf("without bundles the check should warn:\n%s", resultText(r))
	}
}

func TestReleaseCatchesInconsistencies(t *testing.T) {
	for _, c := range []struct {
		name, file, old, new, want string
	}{
		{"manifest edited", "manifest.json", "0.1.29", "0.1.30", "hashes to"},
		{"verdict of another digest", "verdict.json", `"digest": "`, `"digest": "0`, "judges"},
		{"verdict summarises other bytes", "verdict.json", `"bytes": 1912`, `"bytes": 1913`, "summarises"},
		{"passed another commit", "verdict.json", `"commit": "` + releaseCommit + `"
  },
  "manifest"`, `"commit": "` + strings.Repeat("0", 40) + `"
  },
  "manifest"`, "agree"},
		{"pass with a failure code", "verdict.json", `"code": "verified"`, `"code": "unverified"`, "result pass with code"},
		{"another repository id", "verdict.json", `"repositoryId": "111"`, `"repositoryId": "999"`, "the pin is"},
		{"another workflow", "verdict.json", "pipeline.yml@", "other.yml@", "the pin is"},
		{"signers file lost the service", "../../../../../../keys/signers.json", `"vault"`, `"other"`, "pins no identity"},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, dir := releaseDir(t, true)
			path := filepath.Join(root, filepath.FromSlash(dir), c.file)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), c.old) {
				t.Fatalf("test bug: %q not in %s", c.old, c.file)
			}
			if err := os.WriteFile(path, []byte(strings.Replace(string(data), c.old, c.new, 1)), 0o644); err != nil {
				t.Fatal(err)
			}
			r := checkRelease(t, root, dir, ReleaseOptions{})
			if !r.Failed() || !strings.Contains(resultText(r), c.want) {
				t.Errorf("want a failure mentioning %q:\n%s", c.want, resultText(r))
			}
		})
	}
}

func TestReleaseManifestRules(t *testing.T) {
	served := "no-slash"
	for name, m := range map[string]record.ReleaseManifest{
		"unsorted":      {Files: []record.ReleaseFile{{Path: "b"}, {Path: "a"}}},
		"duplicate":     {Files: []record.ReleaseFile{{Path: "a"}, {Path: "a"}}},
		"healthz":       {Files: []record.ReleaseFile{{Path: "healthz"}}},
		"evidence":      {Files: []record.ReleaseFile{{Path: ".well-known/diagnos/manifest.json"}}},
		"served no URL": {Files: []record.ReleaseFile{{Path: "a", Served: &served}}},
	} {
		if manifestProblem(&m) == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	if p := manifestProblem(&record.ReleaseManifest{Files: []record.ReleaseFile{{Path: "a"}, {Path: "b/c"}}}); p != "" {
		t.Errorf("a sorted manifest was rejected: %s", p)
	}
}

// fakeCosign installs a cosign that records its arguments and exits with code.
func fakeCosign(t *testing.T, code int) (binary, log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "calls")
	binary = filepath.Join(dir, "cosign")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\nexit " + string(rune('0'+code)) + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return binary, log
}

func TestReleaseCosignRunsTheTwoCommandsOfTheContract(t *testing.T) {
	root, dir := releaseDir(t, true)
	binary, log := fakeCosign(t, 0)
	r := checkRelease(t, root, dir, ReleaseOptions{Cosign: true, CosignPath: binary})
	if r.Worst() != OK {
		t.Fatalf("cosign accepted, the check failed:\n%s", resultText(r))
	}
	calls, _ := os.ReadFile(log)
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	if len(lines) != 2 {
		t.Fatalf("cosign called %d times:\n%s", len(lines), calls)
	}
	for _, want := range []string{
		"verify-blob --bundle manifest.json.sig", "--certificate-oidc-issuer https://token.actions.githubusercontent.com",
		"--certificate-identity https://github.com/example/monorepo/.github/workflows/pipeline.yml@refs/heads/main",
		"--certificate-github-workflow-repository example/monorepo", "--certificate-github-workflow-ref refs/heads/main",
		"--certificate-github-workflow-sha " + releaseCommit, "manifest.json",
	} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("verify-blob call lacks %q: %s", want, lines[0])
		}
	}
	for _, want := range []string{"verify-blob-attestation --bundle provenance.sigstore.json --type slsaprovenance1", "manifest.json"} {
		if !strings.Contains(lines[1], want) {
			t.Errorf("verify-blob-attestation call lacks %q: %s", want, lines[1])
		}
	}
}

func TestReleaseCosignRejectionAndMissingBundles(t *testing.T) {
	root, dir := releaseDir(t, true)
	binary, _ := fakeCosign(t, 1)
	if r := checkRelease(t, root, dir, ReleaseOptions{Cosign: true, CosignPath: binary}); !r.Failed() {
		t.Error("a release cosign rejects passed")
	}
	if r := checkRelease(t, root, dir, ReleaseOptions{Cosign: true, CosignPath: filepath.Join(t.TempDir(), "no-such-cosign")}); !r.Failed() {
		t.Error("a missing cosign binary passed")
	}
	root, dir = releaseDir(t, false)
	if r := checkRelease(t, root, dir, ReleaseOptions{Cosign: true, CosignPath: binary}); !r.Failed() || !strings.Contains(resultText(r), "not archived") {
		t.Errorf("-cosign on a release without bundles must fail:\n%s", resultText(r))
	}
}
