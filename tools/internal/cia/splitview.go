package cia

import (
	"sort"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// SplitViews lists the logs for which two witnesses read, in the same run, a
// checkpoint of the same size with different roots. Such a log signed two
// different trees: each witness's own consistency checks cannot see it, because
// each saw a tree that was consistent with its own history. Checkpoints of
// different sizes prove nothing without a consistency proof and are left out.
func SplitViews(r *record.CIARunV2) []string {
	seen := map[string]bool{}
	ids := make([]string, 0, len(r.Witnesses))
	for id, e := range r.Witnesses {
		if e.Measured != nil {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for i, a := range ids {
		for _, b := range ids[i+1:] {
			for log, la := range r.Witnesses[a].Measured.Logs {
				lb, ok := r.Witnesses[b].Measured.Logs[log]
				if ok && la.Size != nil && lb.Size != nil && *la.Size == *lb.Size &&
					la.Root != nil && lb.Root != nil && *la.Root != *lb.Root {
					seen[log] = true
				}
			}
		}
	}
	logs := make([]string, 0, len(seen))
	for log := range seen {
		logs = append(logs, log)
	}
	sort.Strings(logs)
	return logs
}
