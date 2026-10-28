package record

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// CIAIncidents is a cia-incidents/v1 snapshot: the published declared
// incidents as the auditor read them from incidents/*.md.
type CIAIncidents struct {
	Schema    string             `json:"schema"`
	ReadAt    string             `json:"readAt"`
	Source    CIAIncidentsSource `json:"source"`
	Incidents []CIAIncident      `json:"incidents"`
}

// CIAIncidentsSource names the commit the incident files were read at.
type CIAIncidentsSource struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Path       string `json:"path"`
}

// Localized is the same text in both languages.
type Localized struct {
	EN   string `json:"en"`
	PTBR string `json:"pt-BR"`
}

// CIAIncident is one published declared incident.
type CIAIncident struct {
	ID         string    `json:"id"`
	Source     string    `json:"source"`
	File       string    `json:"file"`
	Blob       string    `json:"blob"`
	Title      Localized `json:"title"`
	Summary    Localized `json:"summary"`
	Services   []string  `json:"services"`
	Categories []string  `json:"categories"`
	Severity   string    `json:"severity"`
	Status     string    `json:"status"`
	DeclaredAt string    `json:"declaredAt"`
	StartedAt  string    `json:"startedAt"`
	ResolvedAt *string   `json:"resolvedAt"`
	Relates    *string   `json:"relates"`
	Body       Localized `json:"body"`
}

// CIAIncidentEvent is a cia-incident-event/v1 fact: one step in the life of
// an incident the auditor opened on its own.
type CIAIncidentEvent struct {
	Schema     string   `json:"schema"`
	ID         string   `json:"id"`
	Seq        int      `json:"seq"`
	Type       string   `json:"type"`
	At         string   `json:"at"`
	Source     string   `json:"source"`
	Categories []string `json:"categories"`
	Services   []string `json:"services"`
	Severity   string   `json:"severity"`
	StartedAt  string   `json:"startedAt"`
	ResolvedAt *string  `json:"resolvedAt"`
	Reasons    []string `json:"reasons"`
	Run        string   `json:"run"`
}

// CIAAutoIncident is the current state of an automatic incident in the list.
type CIAAutoIncident struct {
	ID          string   `json:"id"`
	Source      string   `json:"source"`
	Categories  []string `json:"categories"`
	Services    []string `json:"services"`
	Severity    string   `json:"severity"`
	Status      string   `json:"status"`
	OpenedAt    string   `json:"openedAt"`
	StartedAt   string   `json:"startedAt"`
	ResolvedAt  *string  `json:"resolvedAt"`
	UpdatedAt   string   `json:"updatedAt"`
	Reasons     []string `json:"reasons"`
	Events      int      `json:"events"`
	LastEvent   string   `json:"lastEvent"`
	Postmortems []string `json:"postmortems"`
}

// CIAListItem is a declared or an automatic incident of the list; exactly one
// of the two is set.
type CIAListItem struct {
	Declared *CIAIncident
	Auto     *CIAAutoIncident
}

// ID and StartedAt are what the list is ordered by.
func (i CIAListItem) ID() string {
	if i.Declared != nil {
		return i.Declared.ID
	}
	return i.Auto.ID
}

func (i CIAListItem) StartedAt() string {
	if i.Declared != nil {
		return i.Declared.StartedAt
	}
	return i.Auto.StartedAt
}

func (i CIAListItem) MarshalJSON() ([]byte, error) {
	switch {
	case i.Declared != nil:
		return json.Marshal(i.Declared)
	case i.Auto != nil:
		return json.Marshal(i.Auto)
	}
	return nil, fmt.Errorf("empty incident")
}

func (i *CIAListItem) UnmarshalJSON(data []byte) error {
	var head struct {
		Source string `json:"source"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	switch head.Source {
	case "declared":
		i.Declared = new(CIAIncident)
		return dec.Decode(i.Declared)
	case "auditor":
		i.Auto = new(CIAAutoIncident)
		return dec.Decode(i.Auto)
	}
	return fmt.Errorf("incident source %q is neither declared nor auditor", head.Source)
}

// CIAIncidentList is the cia-incident-list/v1 view, data/v1/cia/incidents.json.
type CIAIncidentList struct {
	Schema    string           `json:"schema"`
	Declared  *CIAListDeclared `json:"declared"`
	Incidents []CIAListItem    `json:"incidents"`
}

// CIAListDeclared says which declared snapshot the list was made from.
type CIAListDeclared struct {
	Snapshot string `json:"snapshot"`
	Commit   string `json:"commit"`
	ReadAt   string `json:"readAt"`
}

// CIAChanges is the cia-changes/v1 view: the latest change events, newest first.
type CIAChanges struct {
	Schema string      `json:"schema"`
	Events []CIAChange `json:"events"`
}

// CIAChange is one change event.
type CIAChange struct {
	ID         string         `json:"id"`
	At         string         `json:"at"`
	Since      string         `json:"since"`
	Kind       string         `json:"kind"`
	Services   []string       `json:"services"`
	Categories []string       `json:"categories"`
	Dimension  *string        `json:"dimension"`
	From       *string        `json:"from"`
	To         *string        `json:"to"`
	Summary    Localized      `json:"summary"`
	Links      CIAChangeLinks `json:"links"`
}

// CIAChangeLinks points at the evidence of a change event.
type CIAChangeLinks struct {
	Record   *string `json:"record"`
	Incident *string `json:"incident"`
	Finding  *string `json:"finding"`
	Release  *string `json:"release"`
}
