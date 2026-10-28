package cia

import (
	"time"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// WindowDays is how many days the summary covers.
const WindowDays = 90

// DayLetter is the colour of a day for a dimension, from its counts of ok,
// warn and fail slots (CONTRACTS §7.5).
func DayLetter(dimension string, ok, warn, fail int) byte {
	switch {
	case ok+warn+fail == 0:
		return '-'
	case dimension == "availability":
		switch {
		case fail >= 3:
			return 'f'
		case fail >= 1 || warn >= 1:
			return 'w'
		}
	case fail >= 1:
		return 'f'
	case warn >= 1:
		return 'w'
	}
	return 'o'
}

// Counts tallies a day file's letters for one service and dimension:
// [ok, warn, fail, slots that had a run but no measurement].
func Counts(day *record.CIADay, service, dimension string) [4]int {
	var c [4]int
	letters, ok := day.Services[service]
	if !ok {
		return c
	}
	for i, l := range []byte(letters.Dimension(dimension)) {
		switch l {
		case 'o':
			c[0]++
		case 'w':
			c[1]++
		case 'f':
			c[2]++
		default:
			if day.Runs[i] == '1' {
				c[3]++
			}
		}
	}
	return c
}

// BuildSummary derives the 90-day summary from the day files of the window
// ending at day `to` (days maps "YYYY-MM-DD" to the file; a missing day counts
// as zeros). updatedAt is the finish time of the latest run.
func BuildSummary(days map[string]*record.CIADay, firstRun, to time.Time, updatedAt string) *record.CIASummary {
	from := to.AddDate(0, 0, -(WindowDays - 1))
	var window [WindowDays]*record.CIADay
	var present []*record.CIADay
	for k := range window {
		window[k] = days[from.AddDate(0, 0, k).Format(record.DayLayout)]
		if window[k] != nil {
			present = append(present, window[k])
		}
	}
	sum := &record.CIASummary{
		Schema: "cia-summary/v1", UpdatedAt: updatedAt, FirstRun: record.FormatTime(firstRun),
		From: from.Format(record.DayLayout), To: to.Format(record.DayLayout),
		Services: map[string]record.CIASummaryService{},
	}
	seen := map[string]bool{}
	for _, d := range present {
		for id := range d.Services {
			seen[id] = true
		}
	}
	for id := range seen {
		var svc record.CIASummaryService
		for _, name := range record.Dimensions {
			series := svc.Series(name)
			letters := make([]byte, WindowDays)
			for k, d := range window {
				c := [4]int{}
				if d != nil {
					c = Counts(d, id, name)
				}
				series.Counts = append(series.Counts, c)
				letters[k] = DayLetter(name, c[0], c[1], c[2])
				if name == "availability" {
					svc.Uptime.Up += c[0] + c[1]
					svc.Uptime.Measured += c[0] + c[1] + c[2]
				}
			}
			series.Days = string(letters)
		}
		for _, d := range window {
			var p95 *int
			if d != nil && d.Services[id].Latency != nil {
				p95 = d.Services[id].Latency.P95Ms
			}
			svc.P95Ms = append(svc.P95Ms, p95)
		}
		sum.Services[id] = svc
	}
	return sum
}
