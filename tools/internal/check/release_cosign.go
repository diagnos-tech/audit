package check

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// cosignVerify runs the two commands of CONTRACTS §3.7 on a scratch copy of
// the archived files: the signature of manifest.json and the SLSA provenance
// attestation for it, both against the pinned identity.
func cosignVerify(src record.Source, dir string, v *record.CIARelease, pin *record.Signer, opts ReleaseOptions, r *Report) {
	tmp, err := os.MkdirTemp("", "verify-release-")
	if err != nil {
		r.fail("cosign", "%v", err)
		return
	}
	defer os.RemoveAll(tmp)
	for name, from := range map[string]string{
		"manifest.json": dir + "/manifest.json", "manifest.json.sig": *v.Files.Signature, "provenance.sigstore.json": *v.Files.Provenance,
	} {
		data, err := src.Read(from)
		if err == nil {
			err = os.WriteFile(filepath.Join(tmp, name), data, 0o600)
		}
		if err != nil {
			r.fail("cosign", "%v", err)
			return
		}
	}
	binary := opts.CosignPath
	if binary == "" {
		binary = "cosign"
	}
	identity := pin.Repository + "/" + pin.Workflow + "@" + pin.Ref
	repo := strings.TrimPrefix(pin.Repository, "https://github.com/")
	common := []string{"--certificate-oidc-issuer", pin.Issuer, "--certificate-identity", identity}
	commands := []struct {
		name string
		args []string
	}{
		{"cosign signature", append(append([]string{"verify-blob", "--bundle", "manifest.json.sig"}, common...),
			"--certificate-github-workflow-repository", repo, "--certificate-github-workflow-ref", pin.Ref,
			"--certificate-github-workflow-sha", v.Claim.Commit, "manifest.json")},
		{"cosign provenance", append(append([]string{"verify-blob-attestation", "--bundle", "provenance.sigstore.json", "--type", "slsaprovenance1"}, common...),
			"manifest.json")},
	}
	for _, c := range commands {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cmd := exec.CommandContext(ctx, binary, c.args...)
		cmd.Dir = tmp
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		cancel()
		if err != nil {
			r.fail(c.name, "%s %s: %v\n%s", binary, strings.Join(c.args, " "), err, strings.TrimSpace(out.String()))
			continue
		}
		r.pass(c.name, "verified for %s", identity)
	}
}
