package incidents

import (
	"os"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

const valid = `---
id: 2026-10-27-example
title:
  en: "Example: a title with a colon"
  pt-BR: Um título simples
summary:
  en: Something happened to the vault.
  pt-BR: Algo aconteceu com o vault.
services: [vault, sign]
categories: [A, C]
severity: high
status: resolved
declared_at: 2026-10-27T12:00:00Z
started_at: 2026-10-27T11:20:00Z
resolved_at: 2026-10-27T13:05:00Z
publish: true
---

## English

First paragraph.

### What happened

- one
- two

` + "```" + `
# not a heading inside code
` + "```" + `

## Português

Primeiro parágrafo.
`

func TestParseValid(t *testing.T) {
	inc, err := Parse("2026-10-27-example.md", []byte(valid), now)
	if err != nil {
		t.Fatal(err)
	}
	if inc.Title.EN != "Example: a title with a colon" || inc.Severity != "high" || !inc.Publish {
		t.Errorf("unexpected incident %+v", inc)
	}
	if got := strings.Join(inc.Services, ","); got != "vault,sign" {
		t.Errorf("services %s", got)
	}
	if got := strings.Join(inc.Categories, ","); got != "C,A" {
		t.Errorf("categories %s: stored in the order C, I, A", got)
	}
	if inc.Relates != nil {
		t.Errorf("relates %v", *inc.Relates)
	}
	if inc.ResolvedAt == nil || !inc.ResolvedAt.Equal(time.Date(2026, 10, 27, 13, 5, 0, 0, time.UTC)) {
		t.Errorf("resolvedAt %v", inc.ResolvedAt)
	}
	if !strings.HasPrefix(inc.Body.EN, "First paragraph.") || !strings.HasSuffix(inc.Body.EN, "```") {
		t.Errorf("english body %q", inc.Body.EN)
	}
	if inc.Body.PTBR != "Primeiro parágrafo." {
		t.Errorf("portuguese body %q", inc.Body.PTBR)
	}
}

func TestRelatesNamesAnAutomaticIncident(t *testing.T) {
	in := strings.Replace(valid, "publish: true\n", "relates: 2026-10-01-auto-vault-a-0310\npublish: true\n", 1)
	inc, err := Parse("2026-10-27-example.md", []byte(in), now)
	if err != nil || inc.Relates == nil || *inc.Relates != "2026-10-01-auto-vault-a-0310" {
		t.Fatalf("%v %v", inc, err)
	}
	if s := inc.Snapshot("abc"); s.Relates == nil || s.Source != "declared" || strings.Join(s.Categories, "") != "CA" {
		t.Errorf("%+v", s)
	}
}

func TestOptionalFields(t *testing.T) {
	open := strings.NewReplacer("status: resolved", "status: monitoring", "resolved_at: 2026-10-27T13:05:00Z\n", "resolved_at: null\n").Replace(valid)
	inc, err := Parse("2026-10-27-example.md", []byte(open), now)
	if err != nil || inc.ResolvedAt != nil {
		t.Fatalf("resolved_at: null on an open incident: %v %v", inc, err)
	}
	noStart := strings.Replace(valid, "started_at: 2026-10-27T11:20:00Z\n", "", 1)
	inc, err = Parse("2026-10-27-example.md", []byte(noStart), now)
	if err != nil || !inc.StartedAt.Equal(inc.DeclaredAt) {
		t.Fatalf("started_at defaults to declared_at: %v %v", inc, err)
	}
	noResolvedKey := strings.NewReplacer("status: resolved", "status: identified", "resolved_at: 2026-10-27T13:05:00Z\n", "").Replace(valid)
	if _, err := Parse("2026-10-27-example.md", []byte(noResolvedKey), now); err != nil {
		t.Fatalf("resolved_at may be absent while open: %v", err)
	}
}

// Every rule of CONTRACTS §4.1-§4.3 has a case here; the auditor's parser is
// tested with the same table.
func TestRejects(t *testing.T) {
	edit := func(old, new string) func(string) string {
		return func(s string) string {
			if !strings.Contains(s, old) {
				t.Fatalf("test bug: %q not in the template", old)
			}
			return strings.Replace(s, old, new, 1)
		}
	}
	for _, c := range []struct {
		name, want string
		change     func(string) string
		file       string
	}{
		{"file name is not an id", "file name", nil, "README.md"},
		{"file name with a bad date", "file name", nil, "2026-13-01-x.md"},
		{"file name with upper case", "file name", nil, "2026-10-27-Example.md"},
		{"id differs from file name", "must equal the file name", edit("id: 2026-10-27-example", "id: 2026-10-27-other"), ""},
		{"byte order mark", "byte order mark", func(s string) string { return "\xef\xbb\xbf" + s }, ""},
		{"carriage return", "carriage returns", edit("publish: true\n", "publish: true\r\n"), ""},
		{"tab", "tabs", edit("- one", "-\tone"), ""},
		{"invalid UTF-8", "UTF-8", func(s string) string { return s + "\xff\n" }, ""},
		{"too large", "limit", func(s string) string { return s + strings.Repeat("a\n", 40000) }, ""},
		{"no final line feed", "line feed", func(s string) string { return strings.TrimSuffix(s, "\n") }, ""},
		{"does not start with ---", "start with ---", func(s string) string { return "\n" + s }, ""},
		{"front matter not closed", "not closed", edit("publish: true\n---\n", "publish: true\n"), ""},
		{"unknown key", "unknown key", edit("publish: true\n", "publish: true\nowner: me\n"), ""},
		{"duplicate key", "twice", edit("publish: true\n", "publish: true\npublish: false\n"), ""},
		{"blank line in front matter", "expected", edit("severity: high\n", "\nseverity: high\n"), ""},
		{"comment in front matter", "expected", edit("severity: high\n", "# note\nseverity: high\n"), ""},
		{"indented scalar", "expected", edit("severity: high\n", " severity: high\n"), ""},
		{"missing space after colon", "needs a value", edit("severity: high", "severity:high"), ""},
		{"required key missing", `"publish" is required`, edit("publish: true\n", ""), ""},
		{"title not localized", "two indented lines", edit("title:\n  en: \"Example: a title with a colon\"\n  pt-BR: Um título simples\n", "title: Plain\n"), ""},
		{"pt-BR before en", "expected \"  en:\"", edit("  en: \"Example: a title with a colon\"\n  pt-BR: Um título simples\n", "  pt-BR: Um título simples\n  en: \"Example: a title with a colon\"\n"), ""},
		{"title too long", "title.en", edit(`"Example: a title with a colon"`, `"`+strings.Repeat("a", 121)+`"`), ""},
		{"title empty", "title.pt-BR", edit("pt-BR: Um título simples", `pt-BR: ""`), ""},
		{"summary too long", "summary.en", edit("en: Something happened to the vault.", "en: "+strings.Repeat("a", 281)), ""},
		{"plain text starting with a dash", "cannot start", edit("pt-BR: Algo aconteceu com o vault.", "pt-BR: - Algo"), ""},
		{"plain text with colon space", `": "`, edit("en: Something happened to the vault.", "en: Something: happened"), ""},
		{"plain text with space hash", `" #"`, edit("en: Something happened to the vault.", "en: Something #1"), ""},
		{"plain text ending with colon", "end with", edit("en: Something happened to the vault.", "en: Something happened:"), ""},
		{"plain text ending with space", "end with", edit("en: Something happened to the vault.", "en: Something happened "), ""},
		{"bad JSON string", "JSON string", edit(`"Example: a title with a colon"`, `"Example: \q"`), ""},
		{"services not a list", "services must be a list", edit("services: [vault, sign]", "services: vault"), ""},
		{"services no space after comma", "not a service id", edit("[vault, sign]", "[vault,sign]"), ""},
		{"services empty", "not a service id", edit("[vault, sign]", "[]"), ""},
		{"categories missing", `"categories" is required`, edit("categories: [A, C]\n", ""), ""},
		{"categories not a list", "categories must be a list", edit("categories: [A, C]", "categories: C"), ""},
		{"categories empty", "is not a category", edit("categories: [A, C]", "categories: []"), ""},
		{"categories unknown", "is not a category", edit("categories: [A, C]", "categories: [A, X]"), ""},
		{"categories lower case", "is not a category", edit("categories: [A, C]", "categories: [c]"), ""},
		{"categories repeated", "listed twice", edit("categories: [A, C]", "categories: [C, C]"), ""},
		{"categories no space after the comma", "is not a category", edit("categories: [A, C]", "categories: [A,C]"), ""},
		{"categories quoted", "categories must be a list", edit("categories: [A, C]", `categories: "[A, C]"`), ""},
		{"relates not an automatic id", "automatic incident", edit("publish: true\n", "relates: 2026-10-01-vault-timeout\npublish: true\n"), ""},
		{"relates with a bad time", "automatic incident", edit("publish: true\n", "relates: 2026-10-01-auto-vault-a-2460\npublish: true\n"), ""},
		{"relates quoted", "automatic incident", edit("publish: true\n", "relates: \"2026-10-01-auto-vault-a-0310\"\npublish: true\n"), ""},
		{"relates twice", "twice", edit("publish: true\n", "relates: 2026-10-01-auto-vault-a-0310\nrelates: 2026-10-01-auto-vault-a-0310\npublish: true\n"), ""},
		{"slug that starts with auto-", "file name", edit("id: 2026-10-27-example", "id: 2026-10-27-auto-example"), "2026-10-27-auto-example.md"},
		{"services id with a capital", "not a service id", edit("[vault, sign]", "[vault, Mail]"), ""},
		{"services id starting with a digit", "not a service id", edit("[vault, sign]", "[vault, 1mail]"), ""},
		{"services duplicate", "twice", edit("[vault, sign]", "[vault, vault]"), ""},
		{"services more than four", "1 to 4", edit("[vault, sign]", "[vault, sign, audit, frontend, vault]"), ""},
		{"severity", "severity", edit("severity: high", "severity: urgent"), ""},
		{"status", "status", edit("status: resolved", "status: closed"), ""},
		{"time without Z", "RFC 3339", edit("declared_at: 2026-10-27T12:00:00Z", "declared_at: 2026-10-27T12:00:00+00:00"), ""},
		{"time without seconds", "RFC 3339", edit("declared_at: 2026-10-27T12:00:00Z", "declared_at: 2026-10-27T12:00Z"), ""},
		{"started after declared", "not be after declared_at", edit("started_at: 2026-10-27T11:20:00Z", "started_at: 2026-10-27T12:30:00Z"), ""},
		{"resolved before started", "before started_at", edit("resolved_at: 2026-10-27T13:05:00Z", "resolved_at: 2026-10-27T11:00:00Z"), ""},
		{"resolved without resolved_at", "resolved_at is required", edit("resolved_at: 2026-10-27T13:05:00Z\n", ""), ""},
		{"resolved_at null on a resolved incident", "resolved_at is required", edit("resolved_at: 2026-10-27T13:05:00Z", "resolved_at: null"), ""},
		{"resolved_at on an open incident", "only allowed when status is resolved", edit("status: resolved", "status: monitoring"), ""},
		{"declared in the future", "future", edit("declared_at: 2026-10-27T12:00:00Z", "declared_at: 2026-10-28T12:06:00Z"), ""},
		{"publish not boolean", "publish must be", edit("publish: true", "publish: yes"), ""},
		{"publish quoted", "publish must be", edit("publish: true", `publish: "true"`), ""},
		{"body without English heading", "## English", edit("## English", "## Inglês"), ""},
		{"no blank after English heading", "followed by a blank line", edit("## English\n\n", "## English\n"), ""},
		{"no Português heading", "Português", edit("## Português", "## Portugues"), ""},
		{"no blank before Português", "blank line must come before", edit("```\n\n## Português", "```\n## Português"), ""},
		{"no blank after Português", "followed by a blank line", edit("## Português\n\n", "## Português\n"), ""},
		{"empty English text", "must not be empty", func(s string) string {
			return s[:strings.Index(s, "## English")] + "## English\n\n\n## Português\n\nTexto.\n"
		}, ""},
		{"empty Portuguese text", "Português text is empty", edit("Primeiro parágrafo.\n", ""), ""},
		{"level 2 heading in the text", "only ### and #### are allowed", edit("### What happened", "## What happened"), ""},
		{"level 5 heading in the text", "only ### and #### are allowed", edit("### What happened", "##### What happened"), ""},
		{"level 1 heading in the text", "only ### and #### are allowed", edit("### What happened", "# What happened"), ""},
		{"text over 20000 characters", "limit is 20000", edit("First paragraph.", strings.Repeat("a", 20001)), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			name, data := "2026-10-27-example.md", valid
			if c.change != nil {
				data = c.change(data)
			}
			if c.file != "" {
				name = c.file
			}
			_, err := Parse(name, []byte(data), now)
			if err == nil {
				t.Fatalf("accepted; want an error mentioning %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestPlainTextMayHaveColonsInsideAndNonASCII(t *testing.T) {
	in := strings.Replace(valid, "pt-BR: Um título simples", "pt-BR: Exposição às 12:00 em São Paulo", 1)
	inc, err := Parse("2026-10-27-example.md", []byte(in), now)
	if err != nil || inc.Title.PTBR != "Exposição às 12:00 em São Paulo" {
		t.Fatalf("%v %v", inc, err)
	}
}

func TestShippedFiles(t *testing.T) {
	for _, c := range []struct {
		path    string
		publish bool
	}{
		{"../../../incidents/2026-10-27-example.md", false},
		{"../../../examples/incidents/2026-10-27-example.md", false},
		{"../../../examples/incidents/2026-09-30-sign-session-ids-in-logs.md", true},
		{"../../../examples/incidents/2026-10-01-vault-timeout-postmortem.md", true},
	} {
		data, err := os.ReadFile(c.path)
		if err != nil {
			t.Fatal(err)
		}
		name := c.path[strings.LastIndex(c.path, "/")+1:]
		inc, err := Parse(name, data, now)
		if err != nil {
			t.Errorf("%s: %v", c.path, err)
			continue
		}
		if inc.Publish != c.publish {
			t.Errorf("%s: publish = %v", c.path, inc.Publish)
		}
	}
}

func TestIsAutoID(t *testing.T) {
	for id, want := range map[string]bool{
		"2026-10-01-auto-vault-a-0310": true, "2026-10-01-auto-status-i-1335": true, "2026-10-01-auto-vault-c-0310": false,
		"2026-10-01-auto-vault-a-2460": false, "2026-10-01-vault-a-0310": false, "2026-10-01-auto-Vault-a-0310": false,
	} {
		if IsAutoID(id) != want {
			t.Errorf("IsAutoID(%q) = %v", id, !want)
		}
	}
}

func TestBlobHashMatchesGit(t *testing.T) {
	// `printf 'hello\n' | git hash-object --stdin`
	if got := BlobHash([]byte("hello\n")); got != "ce013625030ba8dba906f756967f9e9ca394464a" {
		t.Errorf("BlobHash = %s", got)
	}
}

func TestSnapshotItem(t *testing.T) {
	inc, err := Parse("2026-10-27-example.md", []byte(valid), now)
	if err != nil {
		t.Fatal(err)
	}
	s := inc.Snapshot("abc")
	if s.File != "incidents/2026-10-27-example.md" || s.ResolvedAt == nil || *s.ResolvedAt != "2026-10-27T13:05:00Z" || s.Blob != "abc" {
		t.Errorf("%+v", s)
	}
}

func TestIsFileName(t *testing.T) {
	for name, want := range map[string]bool{
		"2026-10-27-example.md": true, "2026-10-27-a-b-c.md": true, "README.md": false, "SUMMARY.md": false,
		"index.html": false, "2026-10-27.md": false, "2026-10-27-Example.md": false, "2026-10-27--x.md": false, "2026-10-27-auto-vault-a-0310.md": false, "2026-10-27-automatic.md": true,
	} {
		if IsFileName(name) != want {
			t.Errorf("IsFileName(%q) = %v", name, !want)
		}
	}
}
