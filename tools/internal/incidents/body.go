package incidents

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// parseBody reads the text after the front matter (§4.3): "## English", a
// blank line, the English text, a blank line, "## Português", a blank line,
// the Portuguese text. A blank line is an empty line.
func parseBody(lines []string) (record.Localized, error) {
	var out record.Localized
	i := skipBlank(lines, 0)
	if i >= len(lines) || lines[i] != "## English" {
		return out, fmt.Errorf("the body must start with the heading \"## English\"")
	}
	enStart := skipBlank(lines, i+1)
	if enStart == i+1 {
		return out, fmt.Errorf("\"## English\" must be followed by a blank line")
	}
	ptHeading := -1
	for j := enStart; j < len(lines); j++ {
		if lines[j] == "## Português" {
			ptHeading = j
			break
		}
	}
	if ptHeading < 0 {
		return out, fmt.Errorf("the body must have a \"## Português\" heading after the English text")
	}
	if ptHeading == enStart || lines[ptHeading-1] != "" {
		return out, fmt.Errorf("a blank line must come before \"## Português\" and the English text must not be empty")
	}
	ptStart := skipBlank(lines, ptHeading+1)
	if ptStart == ptHeading+1 {
		return out, fmt.Errorf("\"## Português\" must be followed by a blank line")
	}
	var err error
	if out.EN, err = text("English", lines[enStart:ptHeading]); err != nil {
		return out, err
	}
	out.PTBR, err = text("Português", lines[ptStart:])
	return out, err
}

func skipBlank(lines []string, i int) int {
	for i < len(lines) && lines[i] == "" {
		i++
	}
	return i
}

// text trims the blank lines around one language's text and applies the
// rules that hold for it: not empty, at most MaxBody characters, only ### and
// #### headings (outside fenced code).
func text(lang string, lines []string) (string, error) {
	end := len(lines)
	for end > 0 && lines[end-1] == "" {
		end--
	}
	lines = lines[:end]
	if len(lines) == 0 {
		return "", fmt.Errorf("the %s text is empty", lang)
	}
	fenced := false
	for _, l := range lines {
		if strings.HasPrefix(l, "```") {
			fenced = !fenced
			continue
		}
		if m := headingRE.FindStringSubmatch(l); !fenced && m != nil && (len(m[1]) < 3 || len(m[1]) > 4) {
			return "", fmt.Errorf("the %s text has the heading %q: only ### and #### are allowed", lang, l)
		}
	}
	joined := strings.Join(lines, "\n")
	if n := utf8.RuneCountInString(joined); n > MaxBody {
		return "", fmt.Errorf("the %s text has %d characters, the limit is %d", lang, n, MaxBody)
	}
	return joined, nil
}
