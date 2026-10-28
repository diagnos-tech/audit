package record

// ReleaseManifest is a release-manifest/v1: every file of one release.
type ReleaseManifest struct {
	Schema     string        `json:"schema"`
	Service    string        `json:"service"`
	Version    string        `json:"version"`
	Commit     string        `json:"commit"`
	Repository string        `json:"repository"`
	BuiltAt    string        `json:"builtAt"`
	Files      []ReleaseFile `json:"files"`
}

// ReleaseFile is one file of a release; Served is the URL path it is
// returned at verbatim, or nil.
type ReleaseFile struct {
	Path   string  `json:"path"`
	SHA256 string  `json:"sha256"`
	Bytes  int64   `json:"bytes"`
	Served *string `json:"served"`
}

// Healthz is a healthz/v1 answer.
type Healthz struct {
	Schema      string        `json:"schema"`
	OK          bool          `json:"ok"`
	Service     string        `json:"service"`
	Environment string        `json:"environment"`
	Version     string        `json:"version"`
	Commit      *string       `json:"commit"`
	Deployment  *string       `json:"deployment"`
	Build       *HealthzBuild `json:"build"`
}

// HealthzBuild points at a release's evidence.
type HealthzBuild struct {
	Digest     string `json:"digest"`
	Manifest   string `json:"manifest"`
	Signature  string `json:"signature"`
	Provenance string `json:"provenance"`
}

// CIARelease is a cia-release/v1 verdict.
type CIARelease struct {
	Schema       string              `json:"schema"`
	Service      string              `json:"service"`
	Digest       string              `json:"digest"`
	CheckedAt    string              `json:"checkedAt"`
	Result       string              `json:"result"`
	Code         string              `json:"code"`
	Reason       string              `json:"reason"`
	Claim        ReleaseClaim        `json:"claim"`
	Manifest     *ReleaseSummary     `json:"manifest"`
	Signer       *ReleaseSigner      `json:"signer"`
	Transparency ReleaseTransparency `json:"transparency"`
	Files        ReleaseFiles        `json:"files"`
	Verifier     ReleaseVerifier     `json:"verifier"`
}

// ReleaseClaim is what /healthz said.
type ReleaseClaim struct {
	URL     string `json:"url"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// ReleaseSummary summarises the manifest the verdict judged.
type ReleaseSummary struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Files   int    `json:"files"`
	Bytes   int64  `json:"bytes"`
	Served  int    `json:"served"`
}

// ReleaseSigner is the identity in the Fulcio certificate.
type ReleaseSigner struct {
	Issuer       string `json:"issuer"`
	SAN          string `json:"san"`
	Repository   string `json:"repository"`
	RepositoryID string `json:"repositoryId"`
	OwnerID      string `json:"ownerId"`
	Ref          string `json:"ref"`
	Commit       string `json:"commit"`
	Trigger      string `json:"trigger"`
	Runner       string `json:"runner"`
}

// ReleaseTransparency says where each bundle was logged.
type ReleaseTransparency struct {
	Signature  *ReleaseLogEntry `json:"signature"`
	Provenance *ReleaseLogEntry `json:"provenance"`
}

// ReleaseLogEntry is a transparency log entry of a bundle.
type ReleaseLogEntry struct {
	Log   string `json:"log"`
	Index int64  `json:"index"`
	Time  string `json:"time"`
}

// ReleaseFiles names the archived evidence; a nil path was not archived.
type ReleaseFiles struct {
	Manifest   *string `json:"manifest"`
	Signature  *string `json:"signature"`
	Provenance *string `json:"provenance"`
}

// ReleaseVerifier names the tool that judged the release.
type ReleaseVerifier struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Signers is the signers/v1 file, keys/signers.json.
type Signers struct {
	Schema   string            `json:"schema"`
	Services map[string]Signer `json:"services"`
}

// Signer is the only build identity whose signatures count for a service.
type Signer struct {
	Issuer       string `json:"issuer"`
	Repository   string `json:"repository"`
	RepositoryID string `json:"repositoryId"`
	OwnerID      string `json:"ownerId"`
	Workflow     string `json:"workflow"`
	Ref          string `json:"ref"`
}
