package check

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/diagnos-tech/audit/tools/internal/incidents"
	"github.com/diagnos-tech/audit/tools/internal/record"
)

var serviceIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// snapshotReport checks an incidents snapshot: its list is in the order the
// contract fixes, and every incident in it obeys the rules of §4.2.
func snapshotReport(rd *ciaReader, path string) (*Report, *record.CIAIncidents, []byte) {
	r := &Report{Subject: path}
	data, err := rd.read(path)
	if err != nil {
		r.fail("read", "%v", err)
		return r, nil, nil
	}
	var s record.CIAIncidents
	if err := record.Decode(data, "cia-incidents/v1", &s); err != nil {
		r.fail("format", "%v", err)
		return r, nil, data
	}
	if problem := snapshotProblem(path, &s); problem != "" {
		r.fail("incidents", "%s", problem)
		return r, &s, data
	}
	r.pass("incidents", "%d published incident(s), read %s", len(s.Incidents), s.ReadAt)
	return r, &s, data
}

func snapshotProblem(path string, s *record.CIAIncidents) string {
	readAt, err := record.ParseTime(s.ReadAt)
	if err != nil {
		return err.Error()
	}
	if want := record.CIAIncidentsPath(record.SlotOf(readAt)); want != path {
		return fmt.Sprintf("read at %s, so it belongs at %s", s.ReadAt, want)
	}
	for i, in := range s.Incidents {
		if i > 0 {
			prev := s.Incidents[i-1]
			if prev.DeclaredAt < in.DeclaredAt || (prev.DeclaredAt == in.DeclaredAt && prev.ID >= in.ID) {
				return "incidents must be ordered by declaration, newest first, then by id"
			}
		}
		if problem := incidentProblem(in); problem != "" {
			return in.ID + ": " + problem
		}
	}
	return ""
}

func incidentProblem(in record.CIAIncident) string {
	declared, e1 := record.ParseTime(in.DeclaredAt)
	started, e2 := record.ParseTime(in.StartedAt)
	if e1 != nil || e2 != nil {
		return "declaredAt and startedAt must be RFC 3339 UTC times"
	}
	switch {
	case !incidents.IsFileName(in.ID+".md") || in.File != "incidents/"+in.ID+".md":
		return "id and file must be incidents/<id>.md"
	case in.ID[:10] != declared.Format(record.DayLayout):
		return "the id must start with the day of declaration"
	case started.After(declared):
		return "started after it was declared"
	case !slices.Contains([]string{"low", "medium", "high", "critical"}, in.Severity):
		return "unknown severity " + in.Severity
	case !slices.Contains([]string{"investigating", "identified", "monitoring", "resolved"}, in.Status):
		return "unknown status " + in.Status
	case (in.Status == "resolved") != (in.ResolvedAt != nil):
		return "resolvedAt is set if and only if the status is resolved"
	case len(in.Services) < 1 || len(in.Services) > 4:
		return "1 to 4 services"
	}
	for _, id := range in.Services {
		if !serviceIDRE.MatchString(id) {
			return "not a service id: " + id
		}
	}
	if in.ResolvedAt != nil {
		if resolved, err := record.ParseTime(*in.ResolvedAt); err != nil || resolved.Before(started) {
			return "resolved before it started"
		}
	}
	return ""
}
