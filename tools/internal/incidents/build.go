package incidents

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// build turns the fields into an Incident, applying the rules of §4.2.
func build(f map[string]field, fileID string, now time.Time) (*Incident, error) {
	for _, k := range []string{"id", "title", "summary", "services", "categories", "severity", "status", "declared_at", "publish"} {
		if _, ok := f[k]; !ok {
			return nil, fmt.Errorf("the key %q is required", k)
		}
	}
	inc := &Incident{}
	if f["id"].Value != fileID {
		return nil, fmt.Errorf("line %d: id %q must equal the file name %q", f["id"].Line, f["id"].Value, fileID)
	}
	inc.ID = fileID
	for _, k := range []struct {
		key string
		max int
		dst *record.Localized
	}{{"title", MaxTitle, &inc.Title}, {"summary", MaxSummary, &inc.Summary}} {
		v := f[k.key]
		if !v.Localized {
			return nil, fmt.Errorf("line %d: %q takes an en and a pt-BR line", v.Line, k.key)
		}
		for lang, text := range map[string]string{"en": v.EN, "pt-BR": v.PT} {
			if text == "" || utf8.RuneCountInString(text) > k.max {
				return nil, fmt.Errorf("line %d: %s.%s must be 1 to %d characters", v.Line, k.key, lang, k.max)
			}
		}
		*k.dst = record.Localized{EN: v.EN, PTBR: v.PT}
	}
	var err error
	if inc.Services, err = services(f["services"]); err != nil {
		return nil, err
	}
	if inc.Categories, err = categories(f["categories"]); err != nil {
		return nil, err
	}
	if r, ok := f["relates"]; ok {
		if r.Quoted || !IsAutoID(r.Value) {
			return nil, fmt.Errorf("line %d: relates must be the id of an automatic incident (YYYY-MM-DD-auto-<service>-<a|i>-HHMM)", r.Line)
		}
		inc.Relates = &r.Value
	}
	if inc.Severity, err = oneOf(f["severity"], severities, "severity"); err != nil {
		return nil, err
	}
	if inc.Status, err = oneOf(f["status"], statuses, "status"); err != nil {
		return nil, err
	}
	if inc.Publish, err = boolean(f["publish"]); err != nil {
		return nil, err
	}
	return inc, times(inc, f, now)
}

func times(inc *Incident, f map[string]field, now time.Time) error {
	var err error
	if inc.DeclaredAt, err = instant(f["declared_at"], "declared_at", now); err != nil {
		return err
	}
	inc.StartedAt = inc.DeclaredAt
	if s, ok := f["started_at"]; ok {
		if inc.StartedAt, err = instant(s, "started_at", now); err != nil {
			return err
		}
		if inc.StartedAt.After(inc.DeclaredAt) {
			return fmt.Errorf("line %d: started_at must not be after declared_at", s.Line)
		}
	}
	r, has := f["resolved_at"]
	if has && !r.Quoted && r.Value == "null" {
		has = false
	}
	switch {
	case inc.Status == "resolved" && !has:
		return fmt.Errorf("status is resolved, so resolved_at is required")
	case inc.Status != "resolved" && has:
		return fmt.Errorf("line %d: resolved_at is only allowed when status is resolved", r.Line)
	case !has:
		return nil
	}
	t, err := instant(r, "resolved_at", now)
	if err != nil {
		return err
	}
	if t.Before(inc.StartedAt) {
		return fmt.Errorf("line %d: resolved_at must not be before started_at", r.Line)
	}
	inc.ResolvedAt = &t
	return nil
}

func instant(v field, key string, now time.Time) (time.Time, error) {
	t, err := record.ParseTime(v.Value)
	if err != nil {
		return t, fmt.Errorf("line %d: %s: %v", v.Line, key, err)
	}
	if t.After(now.Add(Future)) {
		return t, fmt.Errorf("line %d: %s is in the future", v.Line, key)
	}
	return t, nil
}

func oneOf(v field, allowed map[string]bool, key string) (string, error) {
	if !allowed[v.Value] {
		return "", fmt.Errorf("line %d: %s %q is not one of %s", v.Line, key, v.Value, strings.Join(sortedKeys(allowed), ", "))
	}
	return v.Value, nil
}

func boolean(v field) (bool, error) {
	if !v.Quoted && (v.Value == "true" || v.Value == "false") {
		return v.Value == "true", nil
	}
	return false, fmt.Errorf("line %d: publish must be true or false", v.Line)
}

func services(v field) ([]string, error) {
	if v.Quoted || !strings.HasPrefix(v.Value, "[") {
		return nil, fmt.Errorf("line %d: services must be a list such as [vault, sign]", v.Line)
	}
	items := strings.Split(v.Value[1:len(v.Value)-1], ", ")
	if len(items) < 1 || len(items) > 4 {
		return nil, fmt.Errorf("line %d: services lists 1 to 4 services", v.Line)
	}
	for i, id := range items {
		switch {
		case !identRE.MatchString(id):
			return nil, fmt.Errorf("line %d: %q is not a service id (write [a, b] with \", \" between ids)", v.Line, id)
		case slices.Contains(items[:i], id):
			return nil, fmt.Errorf("line %d: service %q is listed twice", v.Line, id)
		}
	}
	return items, nil
}

// categories reads [C, I, A] in any order and returns the set in the order
// C, I, A.
func categories(v field) ([]string, error) {
	if v.Quoted || !strings.HasPrefix(v.Value, "[") {
		return nil, fmt.Errorf("line %d: categories must be a list such as [C, A]", v.Line)
	}
	items := strings.Split(v.Value[1:len(v.Value)-1], ", ")
	seen := map[string]bool{}
	for _, c := range items {
		switch {
		case c != "C" && c != "I" && c != "A":
			return nil, fmt.Errorf("line %d: %q is not a category: use C (confidentiality), I (integrity) or A (availability), as in [C, I]", v.Line, c)
		case seen[c]:
			return nil, fmt.Errorf("line %d: category %q is listed twice", v.Line, c)
		}
		seen[c] = true
	}
	var out []string
	for _, c := range []string{"C", "I", "A"} {
		if seen[c] {
			out = append(out, c)
		}
	}
	return out, nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

var headingRE = regexp.MustCompile(`^(#{1,6})( |$)`)
