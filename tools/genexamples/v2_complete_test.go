package main

import (
	"strings"
	"testing"

	"github.com/diagnos-tech/audit/tools/internal/check"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

// A history that begins with its first run verifies as a complete history
// (-complete): the chain runs unbroken from the first record, and every day file and
// view is derived from the records alone, with no slice to excuse a difference. That
// includes the regions, their statistics and the events about the witnesses. The
// examples themselves are a slice and fail that check on purpose.
func TestACompleteHistoryVerifies(t *testing.T) {
	saved := firstRun
	firstRun = start
	defer func() { firstRun = saved }()
	dir := t.TempDir()
	if _, err := generateInto(dir); err != nil {
		t.Fatal(err)
	}
	failed, _ := verifyAllWith(t, dir, check.CIAOptions{Complete: true}, false)
	if len(failed) > 0 {
		t.Errorf("%d reports fail:\n%.4000s", len(failed), strings.Join(failed, "\n"))
	}

	// What only the whole history can confirm: a count of retries, a phase, an error class.
	rewrite(t, dir, dayFile, "cia-day/v1", func(d *record.CIADay) {
		s := d.Services["vault"]
		r := s.Regions["latam"]
		r.Retries++
		s.Regions["latam"] = r
		d.Services["vault"] = s
	})
	if failed, _ := verifyAllWith(t, dir, check.CIAOptions{}, false); len(failed) != 0 {
		t.Errorf("a slice of the history cannot tell a count of retries; failures:\n%.1000s", strings.Join(failed, "\n"))
	}
	failed, _ = verifyAllWith(t, dir, check.CIAOptions{Complete: true}, false)
	if all := strings.Join(failed, "\n"); !strings.Contains(all, "differs from the run records") {
		t.Errorf("the whole history did not catch the retries of Latin America; failures:\n%.1000s", all)
	}
}
