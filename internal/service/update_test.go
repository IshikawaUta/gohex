package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IshikawaUta/gohex/internal/audit"
)

func TestUpdateCheckHardDisabled(t *testing.T) {
	app := newTestApp(t)
	t.Setenv("GOHEX_UPDATE_CHECK", "0")
	res, err := app.UpdateCheck()
	if err != nil {
		t.Fatal(err)
	}
	if res.Available || !strings.Contains(res.Error, "GOHEX_UPDATE_CHECK=0") {
		t.Errorf("res = %+v, want disabled result", res)
	}
	if res.Current == "" {
		t.Error("Current empty")
	}

	// No audit record and no network for a hard-disabled check.
	events, err := audit.ReadAll(app.log.Path(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Detail["op"] == "update-check" {
			t.Errorf("disabled check was audited: %+v", e)
		}
	}
}

func TestUpdateCheckDefaultOn(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v99.0.0","html_url":"https://example.com/rel","body":"notes"}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("GOHEX_UPDATE_CHECK", "")
	t.Setenv("GOHEX_UPDATE_URL", srv.URL)

	res, err := app.UpdateCheck()
	if err != nil {
		t.Fatal(err)
	}
	if !res.Available || res.Latest != "99.0.0" {
		t.Errorf("res = %+v", res)
	}

	events, err := audit.ReadAll(app.log.Path(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == audit.ActionConfig && e.Detail["op"] == "update-check" &&
			e.Detail["available"] == "true" && e.Result == audit.ResultOK {
			found = true
		}
	}
	if !found {
		t.Errorf("enabled check not audited; events = %+v", events)
	}
}

func TestUpdateCheckProbeFailureIsSoft(t *testing.T) {
	app := newTestApp(t)
	t.Setenv("GOHEX_UPDATE_CHECK", "")
	t.Setenv("GOHEX_UPDATE_URL", "http://127.0.0.1:1") // nothing listens here

	res, err := app.UpdateCheck()
	if err != nil {
		t.Fatalf("probe failure must not be a Go error: %v", err)
	}
	if res.Available || res.Error == "" {
		t.Errorf("res = %+v, want soft failure", res)
	}
	events, err := audit.ReadAll(app.log.Path(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Detail["op"] == "update-check" && e.Result == audit.ResultError {
			found = true
		}
	}
	if !found {
		t.Errorf("failed probe not audited; events = %+v", events)
	}
}

func TestUpdateDownloadHardDisabled(t *testing.T) {
	app := newTestApp(t)
	t.Setenv("GOHEX_UPDATE_CHECK", "0")
	dst := filepath.Join(t.TempDir(), "asset.bin")
	if _, err := app.UpdateDownload("http://example.invalid/a", strings.Repeat("ab", 32), dst); err == nil {
		t.Fatal("download must be refused when GOHEX_UPDATE_CHECK=0")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("disabled download created %s", dst)
	}
}

func TestUpdateDownloadVerifiesDigest(t *testing.T) {
	app := newTestApp(t)
	payload := []byte("gohex-release-asset")
	sum := sha256.Sum256(payload)
	good := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("GOHEX_UPDATE_CHECK", "")

	dir := t.TempDir()
	dst := filepath.Join(dir, "asset.bin")
	res, err := app.UpdateDownload(srv.URL, good, dst)
	if err != nil {
		t.Fatalf("verified download: %v", err)
	}
	if res.Bytes != int64(len(payload)) || res.SHA256 != good {
		t.Errorf("res = %+v", res)
	}
	got, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, payload) {
		t.Errorf("file = %q, err = %v", got, err)
	}

	// Wrong digest: file must be removed, error returned, audited.
	badDst := filepath.Join(dir, "bad.bin")
	if _, err := app.UpdateDownload(srv.URL, strings.Repeat("00", 32), badDst); err == nil {
		t.Fatal("mismatched digest must fail")
	}
	if _, err := os.Stat(badDst); !os.IsNotExist(err) {
		t.Errorf("mismatch left %s behind", badDst)
	}
	events, err := audit.ReadAll(app.log.Path(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var ok, failed bool
	for _, e := range events {
		if e.Detail["op"] != "update-download" {
			continue
		}
		switch e.Result {
		case audit.ResultOK:
			ok = true
		case audit.ResultError:
			failed = true
		}
	}
	if !ok || !failed {
		t.Errorf("audit trail incomplete: ok=%v failed=%v events=%+v", ok, failed, events)
	}
}
