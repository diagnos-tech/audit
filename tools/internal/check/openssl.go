package check

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/diagnos-tech/audit/tools/internal/record"
)

// OpenSSL runs `openssl ts -verify` for the token of an hourly record,
// against keys/tsa/<provider>.pem.
type OpenSSL struct {
	Binary string        // "openssl" unless set
	Keys   record.Source // where tsa/<provider>.pem lives
	Prefix string        // "keys/" inside a repository, "" for a keys directory
}

// Command is the openssl invocation that verifies a token, printed for
// people who want to run it themselves. The certificates are checked as of
// genTime (-attime), so a token stays verifiable after the TSA's certificate
// expires, which is the point of a timestamp.
func Command(imprint, tsr, caFile string, genTime int64) []string {
	return []string{"ts", "-verify", "-digest", imprint, "-in", tsr, "-CAfile", caFile,
		"-attime", strconv.FormatInt(genTime, 10)}
}

func (o *OpenSSL) verify(der []byte, rec *record.Timestamp, r *Report) {
	tok := rec.Token
	ca, err := o.Keys.Read(o.Prefix + "tsa/" + tok.Provider + ".pem")
	if err != nil {
		r.fail("openssl", "no chain for provider %q: %v", tok.Provider, err)
		return
	}
	dir, err := os.MkdirTemp("", "audit-verify-")
	if err != nil {
		r.fail("openssl", "%v", err)
		return
	}
	defer os.RemoveAll(dir)
	tsr, caFile := filepath.Join(dir, "token.tsr"), filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(tsr, der, 0o600); err != nil {
		r.fail("openssl", "%v", err)
		return
	}
	if err := os.WriteFile(caFile, ca, 0o600); err != nil {
		r.fail("openssl", "%v", err)
		return
	}

	genTime, _ := record.ParseTime(tok.GenTime)
	bin := o.Binary
	if bin == "" {
		bin = "openssl"
	}
	out, err := exec.Command(bin, Command(rec.Imprint, tsr, caFile, genTime.Unix())...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil || !strings.Contains(text, "Verification: OK") {
		r.fail("openssl", "openssl ts -verify: %v\n%s", err, text)
		return
	}
	r.pass("openssl", "TSA signature and chain verify against keys/tsa/%s.pem", tok.Provider)
}

// serialHex renders a serial number the way records store it: big-endian
// bytes in lowercase hex.
func serialHex(b []byte) string {
	if len(b) == 0 {
		return "00"
	}
	return fmt.Sprintf("%x", b)
}
