// Package incidents reads the declared-incident files, incidents/<id>.md, of
// the public record. It implements the grammar of the CIA contract (§4.2 and
// §4.3) exactly and nothing more, so that this verifier and the auditor can be
// written independently and still accept and reject the same files.
package incidents

import (
	"crypto/sha1" //nolint:gosec // Git names blobs by SHA-1; this is an identifier, not a defence.
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// Limits of §4.
const (
	MaxFileBytes = 64 << 10
	MaxTitle     = 120
	MaxSummary   = 280
	MaxBody      = 20000
	// Future is how far past the reader's clock a time may lie.
	Future = 5 * time.Minute
)

var (
	idRE = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])-[a-z0-9]+(-[a-z0-9]+)*$`)
	// autoIDRE is the id of an automatic incident: day of the first slot,
	// "auto", service, category letter, HHMM.
	autoIDRE   = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])-auto-[a-z][a-z0-9-]{0,30}-[ai]-([01][0-9]|2[0-3])[0-5][0-9]$`)
	identRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	severities = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	statuses   = map[string]bool{"investigating": true, "identified": true, "monitoring": true, "resolved": true}
)

// Incident is a parsed, validated incident file.
type Incident struct {
	ID         string
	Title      record.Localized
	Summary    record.Localized
	Services   []string
	Categories []string // C, I, A, in that order
	Severity   string
	Status     string
	DeclaredAt time.Time
	StartedAt  time.Time
	ResolvedAt *time.Time
	Relates    *string // the automatic incident this one adds to
	Publish    bool
	Body       record.Localized
}

// IsFileName reports whether name (a base name) is an incident file name:
// <id>.md with a valid id. Every other file in incidents/ is not an incident.
// The part of the id after the date may not start with "auto-": those ids are
// the automatic incidents', which no file declares.
func IsFileName(name string) bool {
	id, ok := cutSuffix(name, ".md")
	return ok && len(id) <= 80 && idRE.MatchString(id) && !strings.HasPrefix(id[11:], "auto-")
}

// IsAutoID reports whether id has the shape of an automatic incident's id.
func IsAutoID(id string) bool { return len(id) <= 80 && autoIDRE.MatchString(id) }

func cutSuffix(s, suffix string) (string, bool) {
	if len(s) < len(suffix) || s[len(s)-len(suffix):] != suffix {
		return s, false
	}
	return s[:len(s)-len(suffix)], true
}

// Parse reads the file called name (a base name such as
// "2026-09-30-leak.md") with the given bytes. now is the reader's clock; no
// time may be more than Future after it. The first rule broken is returned,
// with its line number when there is one.
func Parse(name string, data []byte, now time.Time) (*Incident, error) {
	if !IsFileName(name) {
		return nil, fmt.Errorf("%q is not an incident file name (<YYYY-MM-DD>-<slug>.md)", name)
	}
	fm, body, err := split(data)
	if err != nil {
		return nil, err
	}
	fields, err := parseFields(fm)
	if err != nil {
		return nil, err
	}
	inc, err := build(fields, name[:len(name)-3], now)
	if err != nil {
		return nil, err
	}
	if inc.Body, err = parseBody(body); err != nil {
		return nil, err
	}
	return inc, nil
}

// Snapshot is the incident as cia-incidents/v1 lists it. blob is the Git blob
// hash of the file (BlobHash).
func (i *Incident) Snapshot(blob string) record.CIAIncident {
	out := record.CIAIncident{
		ID: i.ID, Source: "declared", File: "incidents/" + i.ID + ".md", Blob: blob, Title: i.Title, Summary: i.Summary,
		Services: i.Services, Categories: i.Categories, Severity: i.Severity, Status: i.Status,
		DeclaredAt: record.FormatTime(i.DeclaredAt), StartedAt: record.FormatTime(i.StartedAt), Relates: i.Relates, Body: i.Body,
	}
	if i.ResolvedAt != nil {
		r := record.FormatTime(*i.ResolvedAt)
		out.ResolvedAt = &r
	}
	return out
}

// BlobHash is the hash Git (and the GitHub API) gives the file's content.
func BlobHash(data []byte) string {
	h := sha1.New() //nolint:gosec
	fmt.Fprintf(h, "blob %s\x00", strconv.Itoa(len(data)))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
