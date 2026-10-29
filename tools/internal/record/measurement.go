package record

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// The witnesses of a run record. Europe is the primary witness: it is the only
// clock and the only publisher, so every run record has its entry. Its key
// lives in keys/witness/auditor.vkey for historical reasons; every other
// witness's key is keys/witness/<id>.vkey. A file holds the witness's current
// key and the keys it replaced, one per line.
const (
	WitnessEurope = "europe"
	WitnessLatam  = "latam"
)

// Why a witness's measurement is missing (WitnessEntry.Reason). "off" means the
// witness is not configured: it is not an absence and counts for nothing.
const (
	ReasonTimeout     = "timeout"
	ReasonUnreachable = "unreachable"
	ReasonRejected    = "rejected"
	ReasonSignature   = "signature"
	ReasonInvalid     = "invalid"
	ReasonSkew        = "skew"
	ReasonOff         = "off"
)

// WitnessEntry is one witness in one run: its signed measurement, or why there
// is none. A missing witness is "not measured", never an outage.
type WitnessEntry struct {
	Status string  `json:"status"` // ok or unavailable
	Reason *string `json:"reason"`
	// Note is the witness's signed note over the measurement: the slot, the
	// request it answers and the SHA-256 of the canonical JSON of Measured.
	Note     *string   `json:"note"`
	Measured *Measured `json:"measured"`
	// MeasuredRaw is the measured object exactly as the file spells it. The
	// signed digest is computed over its canonical form, not over a
	// re-encoding of the Go value.
	MeasuredRaw json.RawMessage `json:"-"`
}

// UnmarshalJSON decodes strictly and keeps the raw measured object.
func (e *WitnessEntry) UnmarshalJSON(data []byte) error {
	var aux struct {
		Status   string          `json:"status"`
		Reason   *string         `json:"reason"`
		Note     *string         `json:"note"`
		Measured json.RawMessage `json:"measured"`
	}
	if err := strictUnmarshal(data, &aux); err != nil {
		return err
	}
	*e = WitnessEntry{Status: aux.Status, Reason: aux.Reason, Note: aux.Note}
	if len(aux.Measured) == 0 || string(aux.Measured) == "null" {
		return nil
	}
	e.MeasuredRaw = aux.Measured
	e.Measured = new(Measured)
	return strictUnmarshal(aux.Measured, e.Measured)
}

func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data after the JSON value")
	}
	return nil
}

// Measured is everything one witness measured in one run.
type Measured struct {
	Witness    string                `json:"witness"`
	Vantage    string                `json:"vantage"`
	Slot       string                `json:"slot"`
	StartedAt  string                `json:"startedAt"`
	FinishedAt string                `json:"finishedAt"`
	Control    *CIAControl           `json:"control"`
	Probes     map[string]Probe      `json:"probes"`
	Logs       map[string]WitnessLog `json:"logs"`
	// Peer is the check a secondary witness made of the primary's latest
	// record; nil for the primary witness.
	Peer *WitnessPeer `json:"peer"`
}

// Probe is one witness's GET <url>healthz of one service, on a fresh IPv4
// connection, with one retry. The fields describe the attempt that decided.
type Probe struct {
	Code         string        `json:"code"`
	Class        *string       `json:"class"`
	Attempts     int           `json:"attempts"`
	RetriedAfter *string       `json:"retriedAfter"`
	HTTPStatus   *int          `json:"httpStatus"`
	HTTPVersion  *string       `json:"httpVersion"`
	TLSVersion   *string       `json:"tlsVersion"`
	TLSNotAfter  *string       `json:"tlsNotAfter"`
	TLSIssuer    *string       `json:"tlsIssuer"`
	IP           *string       `json:"ip"`
	Edge         *string       `json:"edge"`
	Bytes        *int          `json:"bytes"`
	Timings      *ProbeTimings `json:"timings"`
	Error        *string       `json:"error"`
}

// ProbeTimings are the non-overlapping phases of an attempt, in whole
// milliseconds from a monotonic clock; a phase that did not happen is nil.
// TotalMs is at least their sum, and the time to first byte is TotalMs less
// TransferMs.
type ProbeTimings struct {
	DNSMs      *int `json:"dnsMs"`
	ConnectMs  *int `json:"connectMs"`
	TLSMs      *int `json:"tlsMs"`
	WaitMs     *int `json:"waitMs"`
	TransferMs *int `json:"transferMs"`
	TotalMs    int  `json:"totalMs"`
}

// WitnessLog is what one witness did with one transparency log in a run.
type WitnessLog struct {
	Code    string  `json:"code"`
	Status  string  `json:"status"`
	Size    *uint64 `json:"size"`
	Root    *string `json:"root"`
	Record  *string `json:"record"`
	Finding *string `json:"finding"`
	Error   *string `json:"error"`
}

// WitnessPeer is the secondary witness's check of the primary's latest
// published run record: ok, gap (not checkable this time), mismatch (the
// published history changed) or unavailable.
type WitnessPeer struct {
	Record  *string `json:"record"`
	SHA256  *string `json:"sha256"`
	Verdict string  `json:"verdict"`
}
