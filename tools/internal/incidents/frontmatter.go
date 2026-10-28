package incidents

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// field is one front matter entry: a scalar (Value) or a localized pair.
type field struct {
	Line      int
	Value     string // the text, or the raw list / literal
	Quoted    bool
	EN, PT    string // localized fields only
	Localized bool
}

const plainStart = "-?:,[]{}#&*!|>'\"%@`"

// split separates the front matter lines from the body and applies the
// whole-file rules: size, UTF-8, no BOM, no CR, no tabs.
func split(data []byte) (front []string, body []string, err error) {
	switch {
	case len(data) > MaxFileBytes:
		return nil, nil, fmt.Errorf("file is %d bytes, the limit is %d", len(data), MaxFileBytes)
	case bytes.HasPrefix(data, []byte("\xef\xbb\xbf")):
		return nil, nil, fmt.Errorf("file starts with a byte order mark")
	case !utf8.Valid(data):
		return nil, nil, fmt.Errorf("file is not valid UTF-8")
	case bytes.IndexByte(data, '\r') >= 0:
		return nil, nil, fmt.Errorf("file has carriage returns: use LF line endings")
	case bytes.IndexByte(data, '\t') >= 0:
		return nil, nil, fmt.Errorf("file has tabs: indent with spaces")
	case len(data) == 0 || data[len(data)-1] != '\n':
		return nil, nil, fmt.Errorf("file does not end with a line feed")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if lines[0] != "---" {
		return nil, nil, fmt.Errorf("line 1: the file must start with ---")
	}
	for i := 1; i < len(lines); i++ {
		if lines[i] == "---" {
			return lines[1:i], lines[i+1:], nil
		}
	}
	return nil, nil, fmt.Errorf("the front matter is not closed by a --- line")
}

var scalarKeys = map[string]bool{"id": true, "services": true, "categories": true, "severity": true, "status": true,
	"declared_at": true, "started_at": true, "resolved_at": true, "relates": true, "publish": true}

// parseFields reads the front matter lines (line numbers count from 2).
func parseFields(lines []string) (map[string]field, error) {
	fields := map[string]field{}
	for i := 0; i < len(lines); i++ {
		n := i + 2
		line := lines[i]
		key, rest, ok := strings.Cut(line, ":")
		if !ok || key == "" || strings.TrimSpace(key) != key || strings.HasPrefix(line, " ") {
			return nil, fmt.Errorf("line %d: expected \"key: value\", found %q", n, line)
		}
		if _, dup := fields[key]; dup {
			return nil, fmt.Errorf("line %d: %q appears twice", n, key)
		}
		switch {
		case key == "title" || key == "summary":
			if rest != "" || i+2 >= len(lines) {
				return nil, fmt.Errorf("line %d: %q takes two indented lines, one for en and one for pt-BR", n, key)
			}
			en, err := localizedLine(lines[i+1], "  en: ", n+1)
			if err != nil {
				return nil, err
			}
			pt, err := localizedLine(lines[i+2], "  pt-BR: ", n+2)
			if err != nil {
				return nil, err
			}
			fields[key] = field{Line: n, EN: en, PT: pt, Localized: true}
			i += 2
		case scalarKeys[key]:
			if !strings.HasPrefix(rest, " ") || rest == " " {
				return nil, fmt.Errorf("line %d: %q needs a value after \"key: \"", n, key)
			}
			text, quoted, err := scalar(rest[1:], n)
			if err != nil {
				return nil, err
			}
			fields[key] = field{Line: n, Value: text, Quoted: quoted}
		default:
			return nil, fmt.Errorf("line %d: unknown key %q", n, key)
		}
	}
	return fields, nil
}

func localizedLine(line, prefix string, n int) (string, error) {
	if !strings.HasPrefix(line, prefix) {
		return "", fmt.Errorf("line %d: expected %q followed by the text", n, strings.TrimRight(prefix, " "))
	}
	text, _, err := scalar(line[len(prefix):], n)
	return text, err
}

// scalar reads the text of a value: a JSON string literal or plain text.
// Lists and literals keep their source form in the result.
func scalar(v string, n int) (text string, quoted bool, err error) {
	if v == "" {
		return "", false, fmt.Errorf("line %d: empty value", n)
	}
	if v[0] == '"' {
		if err := json.Unmarshal([]byte(v), &text); err != nil {
			return "", false, fmt.Errorf("line %d: a quoted value must be one JSON string literal: %v", n, err)
		}
		return text, true, nil
	}
	if v[0] == '[' {
		if !strings.HasSuffix(v, "]") {
			return "", false, fmt.Errorf("line %d: a list must end with ]", n)
		}
		return v, false, nil
	}
	if strings.ContainsRune(plainStart, rune(v[0])) {
		return "", false, fmt.Errorf("line %d: plain text cannot start with %q: quote it", n, v[:1])
	}
	switch {
	case strings.Contains(v, ": "):
		return "", false, fmt.Errorf("line %d: plain text cannot contain \": \": quote it", n)
	case strings.Contains(v, " #"):
		return "", false, fmt.Errorf("line %d: plain text cannot contain \" #\": quote it", n)
	case strings.HasSuffix(v, ":") || strings.HasSuffix(v, " "):
		return "", false, fmt.Errorf("line %d: plain text cannot end with a colon or a space", n)
	}
	return v, false, nil
}
