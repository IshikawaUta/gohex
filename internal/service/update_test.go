package service

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IshikawaUta/gohex/internal/audit"
)

func TestUpdateCheckDisabledByDefault(t *testing.T) {
	app := newTestApp(t)
	t.Setenv("GOHEX_UPDATE_CHECK", "")
	res, err := app.UpdateCheck()
	if err != nil {
		t.Fatal(err)
	}
	if res.Available || !strings.Contains(res.Error, "GOHEX_UPDATE_CHECK") {
		t.Errorf("res = %+v, want disabled result", res)
	}
	if res.Current == "" {
		t.Error("Current empty")
	}

	// No audit record and no network for a disabled check.
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

func TestUpdateCheckEnabled(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v99.0.0","html_url":"https://example.com/rel","body":"notes"}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("GOHEX_UPDATE_CHECK", "1")
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
	t.Setenv("GOHEX_UPDATE_CHECK", "1")
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
