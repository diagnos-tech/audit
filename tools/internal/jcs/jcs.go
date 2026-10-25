// Package jcs serializes JSON per RFC 8785, the JSON Canonicalization Scheme,
// for the values the hourly subject may hold: objects, arrays, strings,
// integers, booleans and null.
//
// Floating-point numbers are rejected rather than canonicalized: the subject
// never has them, and refusing keeps this file free of ECMAScript
// number-formatting rules.
package jcs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

const maxSafeInteger = 1<<53 - 1

// Canonicalize parses JSON text and returns its canonical form.
func Canonicalize(text []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("jcs: trailing data after the JSON value")
	}
	return Marshal(v)
}

// Marshal serializes a value decoded by encoding/json with UseNumber.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encode(buf *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(v))
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil || n > maxSafeInteger || n < -maxSafeInteger {
			return fmt.Errorf("jcs: %s is not a safe integer", v)
		}
		buf.WriteString(strconv.FormatInt(n, 10))
	case string:
		return encodeString(buf, v)
	case []any:
		buf.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encode(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		// RFC 8785 sorts keys by their UTF-16 code units, not by UTF-8 bytes.
		slices.SortFunc(keys, func(a, b string) int {
			return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
		})
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := encode(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("jcs: unsupported type %T", v)
	}
	return nil
}

// encodeString escapes like ECMAScript's JSON.stringify: the two-character
// escapes where they exist, \u00xx for other control characters, and every
// other character as itself.
func encodeString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("jcs: string is not valid UTF-8")
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}
