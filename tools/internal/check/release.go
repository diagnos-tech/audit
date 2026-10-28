package check

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// ReleaseOptions tunes Release.
type ReleaseOptions struct {
	// Cosign also re-checks the archived Sigstore bundles with the cosign
	// command (CONTRACTS §3.7), against the identity pinned in keys/signers.json.
	Cosign bool
	// CosignPath is the cosign binary; empty means "cosign" on PATH.
	CosignPath string
}

var releaseDirRE = regexp.MustCompile(`^data/v1/cia/releases/([a-z][a-z0-9-]{0,30})/([0-9a-f]{64})$`)

// Release checks one archived release directory: the manifest hashes to the
// directory's name, is a well-formed release-manifest/v1 and agrees with the
// verdict; the verdict names the identity pinned for the service; and, with
// opts.Cosign, the bundles verify with cosign.
func Release(src record.Source, dir string, opts ReleaseOptions) *Report {
	r := &Report{Subject: dir}
	m := releaseDirRE.FindStringSubmatch(dir)
	if m == nil {
		r.fail("path", "a release directory is data/v1/cia/releases/<service>/<digest>")
		return r
	}
	service, digest := m[1], m[2]
	manifest := readManifest(src, dir, service, digest, r)
	verdict := readVerdict(src, dir, service, digest, r)
	if manifest == nil || verdict == nil {
		return r
	}
	checkVerdictAgrees(manifest, verdict, dir, r)
	pin := pinnedSigner(src, service, r)
	if pin != nil {
		checkSignerPin(verdict, pin, r)
	}
	checkEvidence(src, dir, verdict, pin, opts, r)
	return r
}

func readManifest(src record.Source, dir, service, digest string, r *Report) *record.ReleaseManifest {
	data, err := src.Read(dir + "/manifest.json")
	if err != nil {
		r.fail("manifest", "%v", err)
		return nil
	}
	var m record.ReleaseManifest
	switch {
	case sum(data) != digest:
		r.fail("manifest", "manifest.json hashes to %s, not to the directory's %s", sum(data), digest)
	case record.Decode(data, "release-manifest/v1", &m) != nil:
		r.fail("manifest", "%v", record.Decode(data, "release-manifest/v1", &m))
	case m.Service != service:
		r.fail("manifest", "describes service %s, not %s", m.Service, service)
	default:
		if problem := manifestProblem(&m); problem != "" {
			r.fail("manifest", "%s", problem)
			return nil
		}
		r.pass("manifest", "%d files, hashes to the directory name", len(m.Files))
		return &m
	}
	return nil
}

// manifestProblem applies the rules of CONTRACTS §3.2 the schema cannot.
func manifestProblem(m *record.ReleaseManifest) string {
	paths := make([]string, len(m.Files))
	for i, f := range m.Files {
		paths[i] = f.Path
		if f.Path == "healthz" || f.Path == "healthz.json" || strings.HasPrefix(f.Path, ".well-known/diagnos/") {
			return fmt.Sprintf("lists %s, which no manifest may list", f.Path)
		}
		if f.Served != nil && !strings.HasPrefix(*f.Served, "/") {
			return fmt.Sprintf("%s is served at %q, which is not a path", f.Path, *f.Served)
		}
	}
	if !slices.IsSorted(paths) || len(slices.Compact(slices.Clone(paths))) != len(paths) {
		return "files must be sorted by path, bytewise, each once"
	}
	return ""
}

func readVerdict(src record.Source, dir, service, digest string, r *Report) *record.CIARelease {
	data, err := src.Read(dir + "/verdict.json")
	if err != nil {
		r.fail("verdict", "%v", err)
		return nil
	}
	var v record.CIARelease
	switch {
	case record.Decode(data, "cia-release/v1", &v) != nil:
		r.fail("verdict", "%v", record.Decode(data, "cia-release/v1", &v))
	case v.Service != service || v.Digest != digest:
		r.fail("verdict", "judges %s %s, not %s %s", v.Service, v.Digest, service, digest)
	case (v.Result == "pass") != (v.Code == "verified"):
		r.fail("verdict", "result %s with code %s", v.Result, v.Code)
	default:
		r.pass("verdict", "%s: %s", v.Result, v.Reason)
		return &v
	}
	return nil
}

// checkVerdictAgrees: what the verdict says of the manifest is the manifest.
func checkVerdictAgrees(m *record.ReleaseManifest, v *record.CIARelease, dir string, r *Report) {
	var bytes int64
	served := 0
	for _, f := range m.Files {
		bytes += f.Bytes
		if f.Served != nil {
			served++
		}
	}
	switch {
	case v.Manifest == nil:
		r.fail("agree", "the verdict has no summary of the manifest")
	case v.Manifest.Version != m.Version || v.Manifest.Commit != m.Commit || v.Manifest.Files != len(m.Files) ||
		v.Manifest.Bytes != bytes || v.Manifest.Served != served:
		r.fail("agree", "the verdict summarises %+v, the manifest has %d files, %d bytes, %d served", *v.Manifest, len(m.Files), bytes, served)
	case v.Result == "pass" && (v.Claim.Version != m.Version || v.Claim.Commit != m.Commit):
		r.fail("agree", "the verdict passed a claim of %s (%s), the manifest is %s (%s)", v.Claim.Version, v.Claim.Commit, m.Version, m.Commit)
	case v.Files.Manifest == nil || *v.Files.Manifest != dir+"/manifest.json":
		r.fail("agree", "files.manifest must name %s/manifest.json", dir)
	default:
		r.pass("agree", "version %s, commit %s", m.Version, m.Commit[:7])
	}
}

func pinnedSigner(src record.Source, service string, r *Report) *record.Signer {
	data, err := src.Read(record.SignersPath)
	if err != nil {
		r.warn("signer", "%v: the identity of the verdict cannot be compared with a pin", err)
		return nil
	}
	var s record.Signers
	if err := record.Decode(data, "signers/v1", &s); err != nil {
		r.fail("signer", "%s: %v", record.SignersPath, err)
		return nil
	}
	pin, ok := s.Services[service]
	if !ok {
		r.fail("signer", "%s pins no identity for %s", record.SignersPath, service)
		return nil
	}
	return &pin
}

func checkSignerPin(v *record.CIARelease, pin *record.Signer, r *Report) {
	if v.Result != "pass" {
		return
	}
	got := v.Signer
	want := pin.Repository + "/" + pin.Workflow + "@" + pin.Ref
	switch {
	case got == nil:
		r.fail("signer", "a passing verdict must name the signer")
	case got.Issuer != pin.Issuer || got.SAN != want || got.Repository != pin.Repository || got.RepositoryID != pin.RepositoryID ||
		got.OwnerID != pin.OwnerID || got.Ref != pin.Ref:
		r.fail("signer", "the verdict names %s (repository %s, owner %s), the pin is %s (repository %s, owner %s)",
			got.SAN, got.RepositoryID, got.OwnerID, want, pin.RepositoryID, pin.OwnerID)
	case got.Commit != v.Claim.Commit:
		r.fail("signer", "the certificate is for commit %s, the release is %s", got.Commit, v.Claim.Commit)
	default:
		r.pass("signer", "%s", want)
	}
}

func checkEvidence(src record.Source, dir string, v *record.CIARelease, pin *record.Signer, opts ReleaseOptions, r *Report) {
	if v.Files.Signature == nil || v.Files.Provenance == nil {
		if opts.Cosign {
			r.fail("evidence", "the Sigstore bundles are not archived, so cosign has nothing to check")
		} else {
			r.warn("evidence", "the Sigstore bundles are not archived (example data carries none); -cosign cannot re-check this release")
		}
		return
	}
	for _, p := range []string{*v.Files.Signature, *v.Files.Provenance} {
		if _, err := src.Read(p); err != nil {
			r.fail("evidence", "%v", err)
			return
		}
	}
	if !opts.Cosign {
		r.pass("evidence", "both bundles are archived (re-check them with -cosign)")
		return
	}
	if pin == nil {
		r.fail("cosign", "no pinned identity to verify against")
		return
	}
	cosignVerify(src, dir, v, pin, opts, r)
}
