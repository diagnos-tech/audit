// Package check verifies the repository's records: the signatures in them,
// the proofs between them and the links that chain them. Every check is
// independent of the witness's code; it uses only the specs and the keys.
package check

import (
	"fmt"
	"io"
	"strings"
)

// Status grades a Result.
type Status int

const (
	OK   Status = iota
	Warn        // worth a look, but not a broken record (e.g. an hour with no token)
	Fail
)

// Result is one named check on one file.
type Result struct {
	Name   string
	Status Status
	Detail string
}

// Report gathers the results for one file (or one comparison).
type Report struct {
	Subject string
	Results []Result
}

func (r *Report) pass(name, format string, args ...any) { r.add(OK, name, format, args...) }
func (r *Report) warn(name, format string, args ...any) { r.add(Warn, name, format, args...) }
func (r *Report) fail(name, format string, args ...any) { r.add(Fail, name, format, args...) }

func (r *Report) add(s Status, name, format string, args ...any) {
	r.Results = append(r.Results, Result{name, s, fmt.Sprintf(format, args...)})
}

// Worst is the most severe status in the report.
func (r *Report) Worst() Status {
	worst := OK
	for _, res := range r.Results {
		worst = max(worst, res.Status)
	}
	return worst
}

// Failed reports whether any check failed.
func (r *Report) Failed() bool { return r.Worst() == Fail }

// Print writes the report; with quiet it writes nothing for a report that
// passed and only the warnings and failures of one that did not.
func (r *Report) Print(w io.Writer, quiet bool) {
	if quiet && r.Worst() == OK {
		return
	}
	fmt.Fprintln(w, r.Subject)
	width := 0
	for _, res := range r.Results {
		width = max(width, len(res.Name))
	}
	for _, res := range r.Results {
		if quiet && res.Status == OK {
			continue
		}
		mark := [...]string{OK: "ok  ", Warn: "warn", Fail: "FAIL"}[res.Status]
		detail := strings.ReplaceAll(res.Detail, "\n", "\n"+strings.Repeat(" ", width+9))
		fmt.Fprintf(w, "  %s %-*s  %s\n", mark, width, res.Name, detail)
	}
}
