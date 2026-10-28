package record

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPSourceReadsAndNamesMissingFiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mirror/data/v1/state.json" {
			w.Write([]byte("{}"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	src, err := Open(context.Background(), srv.Client(), srv.URL+"/mirror")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := src.Read("data/v1/state.json"); err != nil || string(b) != "{}" {
		t.Fatalf("%q %v", b, err)
	}
	_, err = src.Read("./data/v1/audit/witness/2026/09/01/120000Z.json")
	if err == nil {
		t.Fatal("a 404 was not an error")
	}
	want := "data/v1/audit/witness/2026/09/01/120000Z.json: not found at " + srv.URL + "/mirror/ (HTTP 404)"
	if err.Error() != want {
		t.Errorf("error %q\nwant  %q", err, want)
	}
	if !errors.Is(err, ErrNotExist) {
		t.Error("the error must still match ErrNotExist")
	}
}

func TestOtherStatusesAreNotReportedAsMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	src, _ := Open(context.Background(), srv.Client(), srv.URL)
	_, err := src.Read("data/v1/state.json")
	if err == nil || errors.Is(err, ErrNotExist) || !strings.Contains(err.Error(), "500") {
		t.Errorf("a 500 is not a missing file: %v", err)
	}
}

func TestDirSourceMissingFile(t *testing.T) {
	src, err := Open(context.Background(), nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = src.Read("data/v1/state.json")
	if !errors.Is(err, ErrNotExist) || !strings.Contains(err.Error(), "data/v1/state.json") {
		t.Errorf("%v", err)
	}
}

func TestPathsCannotLeaveTheRoot(t *testing.T) {
	src, _ := Open(context.Background(), nil, t.TempDir())
	for _, p := range []string{"../x", "/etc/passwd", "a/../../x", "."} {
		if _, err := src.Read(p); err == nil || errors.Is(err, ErrNotExist) {
			t.Errorf("Read(%q) = %v, want a refusal", p, err)
		}
	}
}
