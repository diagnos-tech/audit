package check

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"

	"github.com/diagnos-tech/audit/tools/internal/jcs"
	"github.com/diagnos-tech/audit/tools/internal/record"
	"github.com/diagnos-tech/audit/tools/internal/rfc3161"
)

// TimestampOptions tunes Timestamp.
type TimestampOptions struct {
	// OpenSSL, when set, also runs `openssl ts -verify` on the token against
	// the provider's chain in the keys directory: the only check here that
	// covers the TSA's signature.
	OpenSSL *OpenSSL
}

// Timestamp checks one hourly record:
//
//   - the imprint is SHA-256 of the RFC 8785 form of the subject;
//   - every witness record the subject names exists, hashes to the given
//     SHA-256 and states the given tree head;
//   - the link to the previous hourly record hashes to the given SHA-256;
//   - the .tsr file hashes to token.sha256 and says what the record says
//     (granted status, imprint, genTime, serial, policy).
func Timestamp(src record.Source, path string, opts TimestampOptions) (*record.Timestamp, *Report) {
	r := &Report{Subject: path}
	data, err := src.Read(path)
	if err != nil {
		r.fail("read", "%v", err)
		return nil, r
	}
	var rec record.Timestamp
	if err := record.Decode(data, "timestamp/v1", &rec); err != nil {
		r.fail("format", "%v", err)
		return nil, r
	}
	hour, err := record.ParseTime(rec.Hour)
	if err != nil || !hour.Equal(hour.Truncate(time.Hour)) || rec.Subject.Hour != rec.Hour {
		r.fail("format", "hour %q must be a whole hour equal to subject.hour %q", rec.Hour, rec.Subject.Hour)
		return nil, r
	}
	if want := record.TimestampPath(hour); want != path {
		r.fail("file name", "the record of %s belongs at %s", rec.Hour, want)
		return nil, r
	}

	canonical, err := jcs.Canonicalize(rec.SubjectRaw)
	if err != nil {
		r.fail("imprint", "subject: %v", err)
		return &rec, r
	}
	if sum := sha256.Sum256(canonical); hex.EncodeToString(sum[:]) != rec.Imprint {
		r.fail("imprint", "SHA-256(JCS(subject)) is %x, the record says %s", sum, rec.Imprint)
	} else {
		r.pass("imprint", "%s = SHA-256(JCS(subject))", rec.Imprint)
	}

	checkSubjectLogs(src, &rec, hour, r)
	checkSubjectCIA(src, &rec, hour, r)
	checkHourLink(src, &rec, hour, r)
	checkToken(src, &rec, hour, r, opts)
	return &rec, r
}

func checkSubjectLogs(src record.Source, rec *record.Timestamp, hour time.Time, r *Report) {
	logs := make([]string, 0, len(rec.Subject.Logs))
	for name := range rec.Subject.Logs {
		logs = append(logs, name)
	}
	slices.Sort(logs)
	for _, name := range logs {
		want := rec.Subject.Logs[name]
		data, err := src.Read(want.Record)
		if err != nil {
			r.fail("subject "+name, "%v", err)
			continue
		}
		if got := sum(data); got != want.SHA256 {
			r.fail("subject "+name, "%s hashes to %s, the subject says %s", want.Record, got, want.SHA256)
			continue
		}
		var w record.Witness
		if err := record.Decode(data, "witness/v1", &w); err != nil {
			r.fail("subject "+name, "%s: %v", want.Record, err)
			continue
		}
		at, _ := record.ParseTime(w.WitnessedAt)
		switch {
		case w.Log != name || w.Origin != want.Origin || w.Checkpoint.Size != want.Size || w.Checkpoint.Root != want.Root:
			r.fail("subject "+name, "%s states %s size %d root %s, the subject says %s size %d root %s",
				want.Record, w.Origin, w.Checkpoint.Size, w.Checkpoint.Root, want.Origin, want.Size, want.Root)
		case !at.Before(hour.Add(time.Hour)):
			r.fail("subject "+name, "%s was witnessed at %s, after the hour", want.Record, w.WitnessedAt)
		default:
			r.pass("subject "+name, "size %d, %s", want.Size, want.Record)
		}
	}
}

func checkHourLink(src record.Source, rec *record.Timestamp, hour time.Time, r *Report) {
	prev := rec.Subject.Prev
	if prev == nil {
		r.pass("chain", "first hourly record: nothing to link to")
		return
	}
	data, err := src.Read(prev.Record)
	if err != nil {
		r.fail("chain", "%v", err)
		return
	}
	if got := sum(data); got != prev.SHA256 {
		r.fail("chain", "%s hashes to %s, the subject says %s", prev.Record, got, prev.SHA256)
		return
	}
	var old record.Timestamp
	if err := record.Decode(data, "timestamp/v1", &old); err != nil {
		r.fail("chain", "%s: %v", prev.Record, err)
		return
	}
	if oldHour, _ := record.ParseTime(old.Hour); !oldHour.Before(hour) {
		r.fail("chain", "%s is for %s, not an earlier hour", prev.Record, old.Hour)
		return
	}
	r.pass("chain", "previous %s, sha256 %s", prev.Record, prev.SHA256)
}

func checkToken(src record.Source, rec *record.Timestamp, hour time.Time, r *Report, opts TimestampOptions) {
	tok := rec.Token
	if tok == nil {
		r.warn("token", "no token this hour: every provider failed (%d attempts); the chain continues", len(rec.Attempts))
		return
	}
	if want := record.TokenPath(hour); tok.File != want {
		r.fail("token", "token file %s, expected %s", tok.File, want)
		return
	}
	der, err := src.Read(tok.File)
	if err != nil {
		r.fail("token", "%v", err)
		return
	}
	if got := sum(der); got != tok.SHA256 {
		r.fail("token", "%s hashes to %s, the record says %s", tok.File, got, tok.SHA256)
		return
	}
	info, err := rfc3161.ParseResponse(der)
	if err != nil {
		r.fail("token", "%v", err)
		return
	}
	genTime := record.FormatTime(info.GenTime.Truncate(time.Second))
	switch {
	case !info.HashAlg.Equal(rfc3161.OIDSHA256):
		r.fail("token", "imprint algorithm %v is not SHA-256", info.HashAlg)
	case hex.EncodeToString(info.Imprint) != rec.Imprint:
		r.fail("token", "token imprint %x, record imprint %s", info.Imprint, rec.Imprint)
	case genTime != tok.GenTime:
		r.fail("token", "token genTime %s, the record says %s", genTime, tok.GenTime)
	case serialHex(info.Serial.Bytes()) != tok.Serial:
		r.fail("token", "token serial %s, the record says %s", serialHex(info.Serial.Bytes()), tok.Serial)
	case info.Policy.String() != tok.Policy:
		r.fail("token", "token policy %v, the record says %s", info.Policy, tok.Policy)
	case info.GenTime.Before(hour.Add(-5*time.Minute)) || !info.GenTime.Before(hour.Add(time.Hour)):
		r.fail("token", "genTime %s is outside the hour %s", tok.GenTime, rec.Hour)
	default:
		hint := ""
		if opts.OpenSSL == nil {
			hint = " (the TSA signature is checked with -openssl)"
		}
		r.pass("token", "%s, genTime %s, serial %s%s", tok.Provider, tok.GenTime, tok.Serial, hint)
	}
	if opts.OpenSSL != nil {
		opts.OpenSSL.verify(der, rec, r)
	}
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// checkSubjectCIA verifies the link to the CIA run record, when the subject
// has one: the file exists, hashes to the given SHA-256 and is a run record of
// the hour or earlier.
func checkSubjectCIA(src record.Source, rec *record.Timestamp, hour time.Time, r *Report) {
	link := rec.Subject.CIA
	if link == nil {
		return
	}
	data, err := src.Read(link.Record)
	if err != nil {
		r.fail("subject cia", "%v", err)
		return
	}
	run, decodeErr := record.DecodeRun(data)
	if run == nil {
		run = &record.CIARun{}
	}
	slot, slotErr := record.ParseTime(run.Slot)
	switch {
	case record.Kind(link.Record) != "cia-run":
		r.fail("subject cia", "%s is not a CIA run record path", link.Record)
	case sum(data) != link.SHA256:
		r.fail("subject cia", "%s hashes to %s, the subject says %s", link.Record, sum(data), link.SHA256)
	case decodeErr != nil || slotErr != nil:
		r.fail("subject cia", "%s is not a run record: %v %v", link.Record, decodeErr, slotErr)
	case record.CIARunPath(slot) != link.Record:
		r.fail("subject cia", "%s is the record of slot %s", link.Record, run.Slot)
	case !slot.Before(hour.Add(time.Hour)):
		r.fail("subject cia", "%s is a run after the hour", link.Record)
	default:
		r.pass("subject cia", "%s", link.Record)
	}
}
