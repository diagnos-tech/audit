package rfc3161

import (
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// The imprint every recorded response was requested for (testdata/README.md).
const imprint = "e038ada4a0546cc9caa33190864444602f35964ba39bed34b741522e8fba01a9"

func TestRealResponses(t *testing.T) {
	for _, provider := range []string{"freetsa", "digicert", "sectigo", "globalsign", "certum", "apple"} {
		der, err := os.ReadFile("testdata/" + provider + ".tsr")
		if err != nil {
			t.Fatal(err)
		}
		info, err := ParseResponse(der)
		if err != nil {
			t.Errorf("%s: %v", provider, err)
			continue
		}
		requested := time.Date(2026, 10, 25, 14, 36, 0, 0, time.UTC)
		switch {
		case info.Status != 0:
			t.Errorf("%s: status %d", provider, info.Status)
		case !info.HashAlg.Equal(OIDSHA256):
			t.Errorf("%s: hash algorithm %v", provider, info.HashAlg)
		case hex.EncodeToString(info.Imprint) != imprint:
			t.Errorf("%s: imprint %x", provider, info.Imprint)
		case info.GenTime.Sub(requested).Abs() > time.Hour:
			t.Errorf("%s: genTime %v", provider, info.GenTime)
		case info.Serial == nil || info.Serial.Sign() <= 0 || len(info.Policy) == 0 || info.Nonce == nil:
			t.Errorf("%s: serial %v, policy %v, nonce %v", provider, info.Serial, info.Policy, info.Nonce)
		}
	}
}

func TestRejectsGarbage(t *testing.T) {
	der, err := os.ReadFile("testdata/freetsa.tsr")
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"empty":     nil,
		"truncated": der[:len(der)/2],
		"trailing":  append(append([]byte(nil), der...), 0),
		"not DER":   []byte("HTTP/1.1 503 Service Unavailable"),
	} {
		if _, err := ParseResponse(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}
