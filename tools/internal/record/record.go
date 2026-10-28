// Package record defines the v1 data files of the repository (see
// schemas/v1/) and how they are named and read.
package record

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Witness is a witness/v1 record.
type Witness struct {
	Schema      string      `json:"schema"`
	Log         string      `json:"log"`
	Origin      string      `json:"origin"`
	URL         string      `json:"url"`
	WitnessedAt string      `json:"witnessedAt"`
	Checkpoint  Checkpoint  `json:"checkpoint"`
	Cosignature Cosignature `json:"cosignature"`
	Previous    *Previous   `json:"previous"`
	Consistency []string    `json:"consistency"`
}

type Checkpoint struct {
	Size uint64 `json:"size"`
	Root string `json:"root"`
	Note string `json:"note"`
}

type Cosignature struct {
	Name    string `json:"name"`
	KeyHash string `json:"keyHash"`
}

type Previous struct {
	Size   uint64 `json:"size"`
	Root   string `json:"root"`
	Record string `json:"record"`
}

// Timestamp is a timestamp/v1 record. Subject is kept as raw JSON as well,
// because the imprint is computed over the canonical form of exactly what
// the file says, not over a re-encoding of the Go struct.
type Timestamp struct {
	Schema     string          `json:"schema"`
	Hour       string          `json:"hour"`
	SubjectRaw json.RawMessage `json:"subject"`
	Subject    Subject         `json:"-"`
	Imprint    string          `json:"imprint"`
	Token      *Token          `json:"token"`
	Attempts   []Attempt       `json:"attempts"`
}

type Subject struct {
	Hour string                `json:"hour"`
	CIA  *Link                 `json:"cia,omitempty"`
	Logs map[string]SubjectLog `json:"logs"`
	Prev *Link                 `json:"prev"`
}

type SubjectLog struct {
	Origin string `json:"origin"`
	Size   uint64 `json:"size"`
	Root   string `json:"root"`
	Record string `json:"record"`
	SHA256 string `json:"sha256"`
}

// Link points at another file and pins its bytes.
type Link struct {
	Record string `json:"record"`
	SHA256 string `json:"sha256"`
}

type Token struct {
	Provider string   `json:"provider"`
	URL      string   `json:"url"`
	File     string   `json:"file"`
	SHA256   string   `json:"sha256"`
	GenTime  string   `json:"genTime"`
	Serial   string   `json:"serial"`
	Policy   string   `json:"policy"`
	TSA      string   `json:"tsa"`
	Checks   []string `json:"checks"`
}

type Attempt struct {
	Provider string `json:"provider"`
	Error    string `json:"error"`
}

// Finding is a finding/v1 record.
type Finding struct {
	Schema      string   `json:"schema"`
	Log         string   `json:"log"`
	Origin      string   `json:"origin"`
	DetectedAt  string   `json:"detectedAt"`
	Kind        string   `json:"kind"`
	Summary     string   `json:"summary"`
	Witnessed   Evidence `json:"witnessed"`
	Observed    Evidence `json:"observed"`
	Consistency []string `json:"consistency"`
}

// Evidence is a tree head with the signed note that states it.
type Evidence struct {
	Size   uint64 `json:"size"`
	Root   string `json:"root"`
	Note   string `json:"note"`
	Record string `json:"record,omitempty"`
}

// FindingSummary is how latest.json and the month index list a finding.
type FindingSummary struct {
	Log        string `json:"log"`
	Kind       string `json:"kind"`
	DetectedAt string `json:"detectedAt"`
	Record     string `json:"record"`
	Summary    string `json:"summary"`
}

// State is state/v1.
type State struct {
	Schema    string              `json:"schema"`
	UpdatedAt string              `json:"updatedAt"`
	Logs      map[string]StateLog `json:"logs"`
	Timestamp *StateTimestamp     `json:"timestamp"`
}

type StateLog struct {
	Origin      string `json:"origin"`
	Size        uint64 `json:"size"`
	Root        string `json:"root"`
	Record      string `json:"record"`
	WitnessedAt string `json:"witnessedAt"`
}

type StateTimestamp struct {
	Hour   string `json:"hour"`
	Record string `json:"record"`
	SHA256 string `json:"sha256"`
}

// Latest is latest/v1.
type Latest struct {
	Schema    string               `json:"schema"`
	UpdatedAt string               `json:"updatedAt"`
	Witness   Cosignature          `json:"witness"`
	Logs      map[string]LatestLog `json:"logs"`
	Timestamp *LatestTimestamp     `json:"timestamp"`
	Findings  []FindingSummary     `json:"findings"`
	Months    []string             `json:"months"`
}

type LatestLog struct {
	Origin       string  `json:"origin"`
	URL          string  `json:"url"`
	CheckedAt    string  `json:"checkedAt"`
	Size         uint64  `json:"size"`
	Root         string  `json:"root"`
	WitnessedAt  string  `json:"witnessedAt"`
	Record       string  `json:"record"`
	PreviousSize *uint64 `json:"previousSize"`
}

type LatestTimestamp struct {
	Hour    string       `json:"hour"`
	Record  string       `json:"record"`
	Imprint string       `json:"imprint"`
	Token   *LatestToken `json:"token"`
}

type LatestToken struct {
	Provider string `json:"provider"`
	GenTime  string `json:"genTime"`
	File     string `json:"file"`
}

// Index is index/v1.
type Index struct {
	Schema     string                  `json:"schema"`
	Month      string                  `json:"month"`
	UpdatedAt  string                  `json:"updatedAt"`
	Logs       map[string][]IndexEntry `json:"logs"`
	Timestamps []IndexTimestamp        `json:"timestamps"`
	Findings   []FindingSummary        `json:"findings"`
}

type IndexEntry struct {
	At     string  `json:"at"`
	Size   uint64  `json:"size"`
	Prev   *uint64 `json:"prev"`
	Root   string  `json:"root"`
	Record string  `json:"record"`
}

type IndexTimestamp struct {
	Hour     string  `json:"hour"`
	Record   string  `json:"record"`
	SHA256   string  `json:"sha256"`
	Imprint  string  `json:"imprint"`
	Prev     *string `json:"prev"`
	Provider *string `json:"provider"`
	GenTime  *string `json:"genTime"`
}

// Decode parses a data file strictly: unknown fields, trailing data and a
// schema tag other than want are errors. The JSON schemas say the same; the
// tools check again so that they never act on a file the schemas reject.
func Decode(data []byte, want string, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data after the JSON object")
	}
	var tag struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Schema != want {
		return fmt.Errorf("schema is %q, want %q", tag.Schema, want)
	}
	if ts, ok := v.(*Timestamp); ok {
		sub := json.NewDecoder(bytes.NewReader(ts.SubjectRaw))
		sub.DisallowUnknownFields()
		if err := sub.Decode(&ts.Subject); err != nil {
			return fmt.Errorf("subject: %w", err)
		}
	}
	return nil
}

// Encode renders a data file the way the witness writes it: two-space
// indentation, no HTML escaping, and a final newline.
func Encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// EncodeCompact renders a view the way the auditor writes it: one line of JSON
// without spaces, no HTML escaping, and a final newline. Views are compact
// because the files that serve them are not compressed and a pretty array
// costs a line per number; facts stay in the indented form, which people read.
// Readers parse either: the tools compare what a file says, not how it is laid
// out.
func EncodeCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
