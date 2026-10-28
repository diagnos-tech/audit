package check

import (
	"os"
	"path/filepath"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/incidents"
)

// Incidents checks incident files given as local paths, against the grammar and
// rules of CONTRACTS §4. A file whose name is not an incident id (README.md,
// SUMMARY.md, ...) is not an incident and is left alone, as the auditor does.
func Incidents(paths []string, now time.Time) []*Report {
	reports := make([]*Report, len(paths))
	for i, p := range paths {
		r := &Report{Subject: p}
		reports[i] = r
		name := filepath.Base(p)
		if !incidents.IsFileName(name) {
			r.pass("name", "not an incident file (<YYYY-MM-DD>-<slug>.md): ignored")
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			r.fail("read", "%v", err)
			continue
		}
		inc, err := incidents.Parse(name, data, now)
		if err != nil {
			r.fail("incident", "%v", err)
			continue
		}
		if inc.Publish {
			r.pass("incident", "valid, published: %s (%s, %s)", inc.ID, inc.Severity, inc.Status)
		} else {
			r.pass("incident", "valid, not published (publish: false): %s", inc.ID)
		}
	}
	return reports
}
