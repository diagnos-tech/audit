package check

import "testing"

const root = "OLDajDFi/5PRy2eGhk/j6TKBonhqGIZh9HJOvkoxXAw="

func TestParseCheckpoint(t *testing.T) {
	for _, c := range []struct {
		body string
		ok   bool
	}{
		{"example.com/log\n42\n" + root + "\n", true},
		{"example.com/log\n42\n" + root + "\nextension line\n", true},
		{"example.com/log\n0\n" + root + "\n", true},
		{"example.com/log\n042\n" + root + "\n", false},     // not canonical decimal
		{"example.com/log\n+42\n" + root + "\n", false},     // sign
		{"example.com/log\n42\n" + root[:43] + "\n", false}, // not base64 of 32 bytes
		{"example.com/log\n42\n" + root, false},             // no final newline
		{"example.com/log\n42\n" + root + "\n\n", false},    // empty extension line
		{"\n42\n" + root + "\n", false},                     // empty origin
		{"example.com/log\n42\n", false},                    // no root
	} {
		_, err := parseCheckpoint(c.body)
		if (err == nil) != c.ok {
			t.Errorf("parseCheckpoint(%q): err = %v, want ok = %v", c.body, err, c.ok)
		}
	}
}

func TestDecodeHashIsStrict(t *testing.T) {
	if _, err := decodeHash(root); err != nil {
		t.Fatal(err)
	}
	// Same bytes, non-canonical padding bits: must be refused, or two strings would name one hash.
	if _, err := decodeHash(root[:42] + "x="); err == nil {
		t.Error("accepted a non-canonical base64 hash")
	}
}
