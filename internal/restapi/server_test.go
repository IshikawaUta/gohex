package restapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IshikawaUta/gohex/internal/service"
)

func newTestServer(t *testing.T) (*Server, *service.App, string) {
	t.Helper()
	app, err := service.New("", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	const token = "test-token-0123456789abcdef"
	srv, err := New(app, token)
	if err != nil {
		t.Fatal(err)
	}
	return srv, app, token
}

func writeEvidence(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "evidence.bin")
	if err := os.WriteFile(p, []byte("GOHEX-SERVER-EVIDENCE-PAYLOAD-0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func do(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuthRequired(t *testing.T) {
	srv, _, _ := newTestServer(t)
	h := srv.Handler()

	// Health is open (liveness only, no evidence data).
	rec := do(t, h, "GET", "/api/v1/health", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("health=%d", rec.Code)
	}
	// Everything else demands the token.
	for _, tc := range []struct{ m, p string }{
		{"GET", "/api/v1/version"},
		{"GET", "/api/v1/documents"},
		{"POST", "/api/v1/documents/open"},
	} {
		rec := do(t, h, tc.m, tc.p, "", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without token = %d, want 401", tc.m, tc.p, rec.Code)
		}
		rec = do(t, h, tc.m, tc.p, "wrong-token", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with bad token = %d, want 401", tc.m, tc.p, rec.Code)
		}
	}
}

func TestOpenReadFindRoundTrip(t *testing.T) {
	srv, _, token := newTestServer(t)
	h := srv.Handler()
	ev := writeEvidence(t)

	rec := do(t, h, "POST", "/api/v1/documents/open", token, map[string]any{"path": ev})
	if rec.Code != http.StatusOK {
		t.Fatalf("open=%d body=%s", rec.Code, rec.Body)
	}
	var doc service.DocInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Size == 0 || doc.ID == 0 {
		t.Fatalf("doc=%+v", doc)
	}

	rec = do(t, h, "GET", fmt.Sprintf("/api/v1/documents/%d", doc.ID), token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("info=%d", rec.Code)
	}

	rec = do(t, h, "GET", fmt.Sprintf("/api/v1/documents/%d/data?offset=0&length=16", doc.ID), token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("data=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "bytes") {
		t.Fatalf("data payload=%s", rec.Body)
	}

	rec = do(t, h, "GET", fmt.Sprintf("/api/v1/documents/%d/find?mode=text&pattern=GOHEX-SERVER", doc.ID), token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("find=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"count":1`) {
		t.Fatalf("find payload=%s", rec.Body)
	}

	// Unknown document → 404.
	rec = do(t, h, "GET", "/api/v1/documents/99999", token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing doc=%d", rec.Code)
	}
}

func TestFsEndpoints(t *testing.T) {
	srv, app, token := newTestServer(t)
	h := srv.Handler()

	// Build a small FAT image via the sample generator? Simpler: use a
	// plain file — probe must fail cleanly, not 500.
	rec := do(t, h, "POST", "/api/v1/fs/probe", token, map[string]any{"path": writeEvidence(t)})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("probe of non-fs = %d", rec.Code)
	}

	// Partitions of a non-image fails cleanly too.
	rec = do(t, h, "GET", "/api/v1/fs/partitions?path="+writeEvidence(t), token, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("partitions=%d", rec.Code)
	}

	// Happy path: open via API then list documents.
	ev := writeEvidence(t)
	rec = do(t, h, "POST", "/api/v1/documents/open", token, map[string]any{"path": ev})
	if rec.Code != http.StatusOK {
		t.Fatalf("open=%d", rec.Code)
	}
	rec = do(t, h, "GET", "/api/v1/documents", token, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "evidence.bin") {
		t.Fatalf("list=%d body=%s", rec.Code, rec.Body)
	}
	_ = app
}

func TestNewRejectsEmptyToken(t *testing.T) {
	app, err := service.New("", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if _, err := New(app, ""); err == nil {
		t.Fatal("empty token accepted")
	}
}

func TestGenerateTokenUnique(t *testing.T) {
	a, b := GenerateToken(), GenerateToken()
	if len(a) != 64 || a == b {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestListenRefusesNonLoopback(t *testing.T) {
	app, err := service.New("", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if err := ListenAndServe(app, "0.0.0.0:9", "tok"); err == nil {
		t.Fatal("non-loopback bind accepted")
	}
	if err := ListenAndServe(app, "not-an-addr", "tok"); err == nil {
		t.Fatal("malformed address accepted")
	}
}
