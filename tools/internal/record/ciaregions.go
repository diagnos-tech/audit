package record

// The per-witness parts of the CIA views. A witness is a region of the world
// the services are measured from: a view lists them side by side, and the
// combined result of a service stays where it has always been.

// CIADayRegion is one UTC day of one service as one witness saw it.
type CIADayRegion struct {
	// Availability has one letter per slot, from the level of the witness's
	// probe: o, w or f, and - where the slot has no record or the witness did
	// not measure.
	Availability string       `json:"availability"`
	Latency      LatencyStats `json:"latency"`
	Phases       PhaseSet     `json:"phases"`
	Errors       ErrorCounts  `json:"errors"`
	// Retries counts the slots whose probe needed two attempts.
	Retries int       `json:"retries"`
	Uptime  CIAUptime `json:"uptime"`
}

// LatencyStats are the nearest-rank percentiles, the minimum (p0), the
// maximum (p100) and the mean of the latency of a witness's successful probes
// over a day, and the latency of every slot they come from. The statistics are
// nil when Samples is 0.
type LatencyStats struct {
	Samples int  `json:"samples"`
	MinMs   *int `json:"minMs"`
	P50Ms   *int `json:"p50Ms"`
	P75Ms   *int `json:"p75Ms"`
	P90Ms   *int `json:"p90Ms"`
	P95Ms   *int `json:"p95Ms"`
	P99Ms   *int `json:"p99Ms"`
	MaxMs   *int `json:"maxMs"`
	MeanMs  *int `json:"meanMs"`
	// SlotsMs is the totalMs of the witness's probe in each of the 288 slots
	// where it succeeded, nil elsewhere.
	SlotsMs []*int `json:"slotsMs"`
}

// PhaseStats is one timing phase over the day's successful probes where it
// was measured: the mean and two percentiles. All nil without a sample.
type PhaseStats struct {
	MeanMs *int `json:"meanMs"`
	P50Ms  *int `json:"p50Ms"`
	P95Ms  *int `json:"p95Ms"`
}

// PhaseSet has the five phases of a probe.
type PhaseSet struct {
	DNSMs      PhaseStats `json:"dnsMs"`
	ConnectMs  PhaseStats `json:"connectMs"`
	TLSMs      PhaseStats `json:"tlsMs"`
	WaitMs     PhaseStats `json:"waitMs"`
	TransferMs PhaseStats `json:"transferMs"`
}

// ErrorClasses lists the classes a failed probe is counted under, in the order
// ErrorCounts has them.
var ErrorClasses = [...]string{"dns", "connect", "tls", "timeout", "http-5xx", "http-4xx", "assertion"}

// ErrorCounts is how many slots of the day failed in each class.
type ErrorCounts struct {
	DNS       int `json:"dns"`
	Connect   int `json:"connect"`
	TLS       int `json:"tls"`
	Timeout   int `json:"timeout"`
	HTTP5xx   int `json:"http-5xx"`
	HTTP4xx   int `json:"http-4xx"`
	Assertion int `json:"assertion"`
}

// Add counts one failure of the class; it reports false for an unknown class.
func (e *ErrorCounts) Add(class string) bool {
	switch class {
	case "dns":
		e.DNS++
	case "connect":
		e.Connect++
	case "tls":
		e.TLS++
	case "timeout":
		e.Timeout++
	case "http-5xx":
		e.HTTP5xx++
	case "http-4xx":
		e.HTTP4xx++
	case "assertion":
		e.Assertion++
	default:
		return false
	}
	return true
}

// Total is the number of failures counted.
func (e ErrorCounts) Total() int {
	return e.DNS + e.Connect + e.TLS + e.Timeout + e.HTTP5xx + e.HTTP4xx + e.Assertion
}

// CIASummaryRegion is the 90 days of one service as one witness saw them.
type CIASummaryRegion struct {
	Days   string    `json:"days"`
	Uptime CIAUptime `json:"uptime"`
	// P50Ms and P95Ms are, per day, oldest first, the percentiles of that
	// day's file; nil where the day has no file or no samples.
	P50Ms []*int `json:"p50Ms"`
	P95Ms []*int `json:"p95Ms"`
}

// CIALatestRegion is one witness's probe of a service in the latest run.
type CIALatestRegion struct {
	Level     string `json:"level"`
	Code      string `json:"code"`
	LatencyMs *int   `json:"latencyMs"`
	Since     string `json:"since"`
}

// CIALatestWitness is whether one witness measured in the latest run.
type CIALatestWitness struct {
	Status  string  `json:"status"`
	Reason  *string `json:"reason"`
	Vantage *string `json:"vantage"`
	Since   string  `json:"since"`
}
