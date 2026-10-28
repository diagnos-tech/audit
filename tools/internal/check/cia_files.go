package check

import (
	"path"
	"strings"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// CIAFiles checks the CIA record of the repository at dir. With files it
// reports on those only (the others are still read, because the views are
// derived from them); without, on every file of the CIA layout.
func CIAFiles(dir string, src record.Source, files []string, opts CIAOptions) ([]*Report, error) {
	t, err := walk(dir)
	if err != nil {
		return nil, err
	}
	var reports []*Report
	for _, p := range t.strangers {
		if strings.HasPrefix(p, "data/v1/cia/") {
			r := &Report{Subject: p}
			r.fail("layout", "this file has no place in the CIA layout (see CONTRACTS §7.1)")
			reports = append(reports, r)
		}
	}
	reports = append(reports, CIA(src, &t.cia, opts)...)
	if len(files) == 0 {
		return reports, nil
	}
	bySubject := map[string]*Report{}
	for _, r := range reports {
		bySubject[r.Subject] = r
	}
	var out []*Report
	for _, f := range files {
		if r, ok := bySubject[subjectOf(f)]; ok {
			out = append(out, r)
			continue
		}
		r := &Report{Subject: f}
		r.fail("exists", "this is not a file of the CIA record in %s (see CONTRACTS §7.1), or it does not exist", dir)
		out = append(out, r)
	}
	return out, nil
}

// subjectOf is what the reports are filed under: a file of a release is
// reported with its directory.
func subjectOf(file string) string {
	switch record.Kind(file) {
	case "release-verdict", "release-manifest", "release-evidence":
		return path.Dir(file)
	}
	return file
}
