package check

import (
	"fmt"
	"sort"
	"strings"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// ciaReader reads repository files once.
type ciaReader struct {
	src   record.Source
	cache map[string][]byte
	miss  map[string]error
}

func newCIAReader(src record.Source) *ciaReader {
	return &ciaReader{src: src, cache: map[string][]byte{}, miss: map[string]error{}}
}

func (c *ciaReader) read(path string) ([]byte, error) {
	if b, ok := c.cache[path]; ok {
		return b, nil
	}
	if err, ok := c.miss[path]; ok {
		return nil, err
	}
	b, err := c.src.Read(path)
	if err != nil {
		c.miss[path] = err
		return nil, err
	}
	c.cache[path] = b
	return b, nil
}

func (c *ciaReader) exists(path string) bool {
	_, err := c.read(path)
	return err == nil
}

// checkChain verifies that each run record links the one before it by the
// SHA-256 of its bytes. Without complete, the oldest record present may link
// one that is not here (the files are a slice of a longer history).
func checkChain(rd *ciaReader, paths []string, datas [][]byte, recs []*record.CIARun, reports []*Report, complete bool) {
	for i, rec := range recs {
		if rec == nil {
			continue
		}
		r, prev := reports[i], rec.Prev
		switch {
		case i == 0 && prev == nil:
			r.pass("chain", "first record of the chain")
		case i == 0 && complete:
			r.fail("chain", "links %s, but with -complete the oldest record must be the first run", prev.Record)
		case i == 0:
			checkMissingPrev(rd, prev, rec, r)
		case prev == nil:
			r.fail("chain", "claims to be the first run, but %s precedes it", paths[i-1])
		case prev.Record != paths[i-1]:
			r.fail("chain", "links %s, but the record before it is %s", prev.Record, paths[i-1])
		case datas[i-1] == nil:
			r.fail("chain", "cannot compare with %s, which could not be read", paths[i-1])
		case sum(datas[i-1]) != prev.SHA256:
			r.fail("chain", "%s hashes to %s, the link says %s", prev.Record, sum(datas[i-1]), prev.SHA256)
		default:
			r.pass("chain", "follows %s", prev.Record)
		}
	}
}

func checkMissingPrev(rd *ciaReader, prev *record.Link, rec *record.CIARun, r *Report) {
	if rd.exists(prev.Record) {
		r.fail("chain", "links %s, which exists but is not the record before it", prev.Record)
		return
	}
	r.pass("chain", "oldest record present; it links %s, which is outside these files", prev.Record)
}

// snapshotFor is the incidents snapshot in force in a slot: the newest of the
// snapshot paths (sorted) written at or before it, or "".
func snapshotFor(snapshots []string, slot string) string {
	want := record.CIAIncidentsPath(mustTime(slot))
	i := sort.SearchStrings(snapshots, want)
	if i < len(snapshots) && snapshots[i] == want {
		return want
	}
	if i == 0 {
		return ""
	}
	return snapshots[i-1]
}

func checkSnapshotLink(rd *ciaReader, snapshots []string, rec *record.CIARun, complete bool, r *Report) {
	want := snapshotFor(snapshots, rec.Slot)
	link := rec.Incidents.Snapshot
	switch {
	case link == nil && want == "":
		r.pass("snapshot", "no incidents snapshot yet")
	case link == nil:
		r.fail("snapshot", "names no snapshot, but %s was already in force", want)
	case want == "" && complete:
		r.fail("snapshot", "names %s, which does not exist", link.Record)
	case want == "":
		r.pass("snapshot", "names %s, which is outside these files", link.Record)
	case link.Record != want:
		r.fail("snapshot", "names %s, but the snapshot in force was %s", link.Record, want)
	default:
		data, err := rd.read(want)
		switch {
		case err != nil:
			r.fail("snapshot", "%v", err)
		case sum(data) != link.SHA256:
			r.fail("snapshot", "%s hashes to %s, the run says %s", want, sum(data), link.SHA256)
		default:
			r.pass("snapshot", "%s", want)
		}
	}
}

// checkRunLinks follows the files a run record points at: the verdicts of its
// releases and the witness records and findings of its log checks.
func checkRunLinks(rd *ciaReader, rec *record.CIARun, r *Report) {
	for _, id := range sortedKeys(rec.Services) {
		for _, c := range append(rec.Services[id].Integrity.Checks, rec.Services[id].Availability.Checks...) {
			var problem string
			switch {
			case c.Release != nil && c.Release.Verdict != nil:
				problem = verdictProblem(rd, id, c.Release)
			case c.Log != nil:
				problem = logProblem(rd, c.Log)
			}
			if problem != "" {
				r.fail("links "+id, "%s: %s", c.ID(), problem)
			}
		}
	}
}

func verdictProblem(rd *ciaReader, service string, x *record.ReleaseCheck) string {
	data, err := rd.read(*x.Verdict)
	if err != nil {
		return err.Error()
	}
	var v record.CIARelease
	if err := record.Decode(data, "cia-release/v1", &v); err != nil {
		return fmt.Sprintf("%s: %v", *x.Verdict, err)
	}
	if v.Service != service || v.Digest != *x.Digest || record.ReleaseDir(v.Service, v.Digest)+"/verdict.json" != *x.Verdict {
		return fmt.Sprintf("%s is not the verdict of %s %s", *x.Verdict, service, *x.Digest)
	}
	if v.Result == "pass" && (v.Claim.Version != *x.Version || v.Claim.Commit != *x.Commit) {
		return fmt.Sprintf("the verdict judged %s (%s), the run says %s (%s)", v.Claim.Version, v.Claim.Commit, *x.Version, *x.Commit)
	}
	return ""
}

func logProblem(rd *ciaReader, x *record.LogCheck) string {
	name := strings.TrimPrefix(x.ID, "log:")
	if x.Record != nil {
		var w record.Witness
		data, err := rd.read(*x.Record)
		if err != nil {
			return err.Error()
		}
		if err := record.Decode(data, "witness/v1", &w); err != nil {
			return fmt.Sprintf("%s: %v", *x.Record, err)
		}
		if w.Log != name || (x.Size != nil && w.Checkpoint.Size != *x.Size) {
			return fmt.Sprintf("%s is the record of log %s at size %d, not %s at %v", *x.Record, w.Log, w.Checkpoint.Size, name, derefSize(x.Size))
		}
	}
	if x.Finding != nil {
		var f record.Finding
		data, err := rd.read(*x.Finding)
		if err != nil {
			return err.Error()
		}
		if err := record.Decode(data, "finding/v1", &f); err != nil {
			return fmt.Sprintf("%s: %v", *x.Finding, err)
		}
		if f.Log != name {
			return fmt.Sprintf("%s is a finding about log %s", *x.Finding, f.Log)
		}
	}
	return ""
}

func derefSize(p *uint64) any {
	if p == nil {
		return "no size"
	}
	return *p
}
