package check

import "github.com/diagnos-tech/audit/tools/internal/record"

// secondaryWitnessReports checks the records of the witnesses other than the
// primary one, each chain on its own: a witness cosigns a log's checkpoints
// independently and keeps its own history of them.
func secondaryWitnessReports(src record.Source, keys *Keyring, t *tree) []*Report {
	var reports []*Report
	for _, wid := range sortedKeys(t.secondary) {
		for _, log := range sortedKeys(t.secondary[wid]) {
			paths := t.secondary[wid][log]
			for i, p := range paths {
				rec, r := Witness(src, keys, p)
				if rec != nil {
					linkCheck(r, "chain", i, rec.Previous == nil, prevRecord(rec), paths)
				}
				reports = append(reports, r)
			}
		}
	}
	return reports
}
