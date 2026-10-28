package main

import (
	"fmt"
	"sort"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// The example releases are signed by an example identity, never by the real
// pipelines pinned in the repository's keys/signers.json: examples/keys has
// its own signers.json, and the Sigstore bundles are not archived (a bundle
// would need a real signing certificate).
const (
	exampleOrg       = "https://github.com/diagnos-example"
	exampleOwnerID   = "100000000"
	exampleIssuer    = "https://token.actions.githubusercontent.com"
	exampleVerifier  = "v1.3.0"
	servedSampleSize = 25
)

var exampleSigners = map[string]record.Signer{
	"status":   exampleSigner("monorepo", "100000001", ".github/workflows/pipeline.yml", "refs/heads/main"),
	"frontend": exampleSigner("monorepo", "100000001", ".github/workflows/pipeline.yml", "refs/heads/main"),
	"sign":     exampleSigner("monorepo", "100000001", ".github/workflows/pipeline.yml", "refs/heads/main"),
	"vault":    exampleSigner("monorepo", "100000001", ".github/workflows/pipeline.yml", "refs/heads/main"),
}

func exampleSigner(repo, id, workflow, ref string) record.Signer {
	return record.Signer{Issuer: exampleIssuer, Repository: exampleOrg + "/" + repo, RepositoryID: id,
		OwnerID: exampleOwnerID, Workflow: workflow, Ref: ref}
}

// release is one judged release of one service and everything archived for it.
type release struct {
	service, version, commit, digest string
	builtAt, firstSeen, checkedAt    time.Time
	manifest                         []byte
	summary                          record.ReleaseSummary
	verdict                          []byte
}

func (r *release) dir() string         { return record.ReleaseDir(r.service, r.digest) }
func (r *release) verdictPath() string { return r.dir() + "/verdict.json" }

// releaseSpec describes a release; the files are derived from the label.
type releaseSpec struct {
	service, version, commit string
	built, seen, done        string // 2006-01-02T15:04:05Z
	files                    []fileSpec
}

type fileSpec struct {
	path   string
	served string // "" = not served verbatim
	bytes  int64
}

func newRelease(s releaseSpec) (*release, error) {
	signer := exampleSigners[s.service]
	r := &release{service: s.service, version: s.version, commit: s.commit}
	var err error
	if r.builtAt, err = record.ParseTime(s.built); err != nil {
		return nil, err
	}
	if r.firstSeen, err = record.ParseTime(s.seen); err != nil {
		return nil, err
	}
	if r.checkedAt, err = record.ParseTime(s.done); err != nil {
		return nil, err
	}
	m := record.ReleaseManifest{Schema: "release-manifest/v1", Service: s.service, Version: s.version, Commit: r.commit,
		Repository: signer.Repository, BuiltAt: s.built}
	sort.Slice(s.files, func(i, j int) bool { return s.files[i].path < s.files[j].path })
	for _, f := range s.files {
		entry := record.ReleaseFile{Path: f.path, SHA256: sum([]byte(s.service + " " + s.version + " " + f.path)), Bytes: f.bytes}
		if f.served != "" {
			served := f.served
			entry.Served = &served
			r.summary.Served++
		}
		r.summary.Bytes += f.bytes
		m.Files = append(m.Files, entry)
	}
	r.summary.Version, r.summary.Commit, r.summary.Files = s.version, r.commit, len(m.Files)
	if r.manifest, err = record.Encode(m); err != nil {
		return nil, err
	}
	r.digest = sum(r.manifest)
	r.verdict, err = record.Encode(r.verdictRecord(signer))
	return r, err
}

func (r *release) verdictRecord(signer record.Signer) record.CIARelease {
	manifest := r.dir() + "/manifest.json"
	logEntry := func(offset int64) *record.ReleaseLogEntry {
		return &record.ReleaseLogEntry{Log: "rekor.example", Index: 4_000_000 + int64(len(r.digest))*offset + offset,
			Time: record.FormatTime(r.builtAt.Add(time.Duration(90+offset) * time.Second))}
	}
	summary := r.summary
	return record.CIARelease{
		Schema: "cia-release/v1", Service: r.service, Digest: r.digest, CheckedAt: record.FormatTime(r.checkedAt),
		Result: "pass", Code: "verified",
		Reason:   "Signature and SLSA provenance verified for the pinned identity; manifest agrees with /healthz.",
		Claim:    record.ReleaseClaim{URL: serviceURL(r.service) + "healthz", Version: r.version, Commit: r.commit},
		Manifest: &summary,
		Signer: &record.ReleaseSigner{Issuer: signer.Issuer, SAN: signer.Repository + "/" + signer.Workflow + "@" + signer.Ref,
			Repository: signer.Repository, RepositoryID: signer.RepositoryID, OwnerID: signer.OwnerID, Ref: signer.Ref,
			Commit: r.commit, Trigger: "push", Runner: "github-hosted"},
		Transparency: record.ReleaseTransparency{Signature: logEntry(1), Provenance: logEntry(2)},
		Files:        record.ReleaseFiles{Manifest: &manifest},
		Verifier:     record.ReleaseVerifier{Name: "sigstore-go", Version: exampleVerifier},
	}
}

// servedChecked is how many served files the integrity function has compared
// at t: it samples a few dozen every minute from the moment it sees the digest.
func (r *release) servedChecked(t time.Time) int {
	minutes := int(t.Sub(r.firstSeen) / time.Minute)
	return max(0, min(r.summary.Served, servedSampleSize*minutes))
}

func (r *release) writeTo(w *writer) error {
	if err := w.raw(r.verdictPath(), r.verdict); err != nil {
		return err
	}
	return w.raw(r.dir()+"/manifest.json", r.manifest)
}

func serviceURL(id string) string {
	host := map[string]string{"frontend": "diagnos.example", "vault": "vault.diagnos.example",
		"sign": "sign.diagnos.example", "status": "status.diagnos.example"}[id]
	return fmt.Sprintf("https://%s/", host)
}
