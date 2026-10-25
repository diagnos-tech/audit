package jcs

import "testing"

func TestCanonicalize(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{
			// RFC 8785 section 3.2.3: keys sort by UTF-16 code units.
			name: "rfc8785 sorting",
			in: `{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh",
			      "1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`,
			want: "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\"," +
				"\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}",
		},
		{
			// RFC 8785 section 3.2.2.2: string escaping.
			name: "rfc8785 strings",
			in:   `"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/"`,
			want: "\"\u20ac$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"",
		},
		{
			name: "subject shape",
			in:   "{ \"prev\": null, \"logs\": {\"signs\": {\"size\": 12}, \"audit\": {\"size\": 9007199254740991}}, \"hour\": \"2026-10-25T14:00:00Z\" }",
			want: `{"hour":"2026-10-25T14:00:00Z","logs":{"audit":{"size":9007199254740991},"signs":{"size":12}},"prev":null}`,
		},
		{name: "arrays and literals", in: `[true, false, null, -0, [ ]]`, want: `[true,false,null,0,[]]`},
	} {
		got, err := Canonicalize([]byte(c.in))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
}

func TestRejects(t *testing.T) {
	for _, in := range []string{`1.5`, `1e3`, `9007199254740992`, `{"a":1} {}`, `{"a":`} {
		if got, err := Canonicalize([]byte(in)); err == nil {
			t.Errorf("Canonicalize(%s) = %s, want an error", in, got)
		}
	}
}
