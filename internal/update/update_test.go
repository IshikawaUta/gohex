package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCompare(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"v1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.10.0", "1.9.9", 1},
		{"2.0", "2.0.0", 0},
		{"1.0", "1.0.0", 0},
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.0", "1.0.0-rc1", 1},
		{"1.0.0-rc2", "1.0.0-rc1", 1},
		{"1.0.0-rc1", "1.0.0-rc2", -1},
		{"1.0.0+build5", "1.0.0+build9", 0},
		{"0.1.0-dev", "0.1.0", -1},
		{"0.2.0", "0.1.0-dev", 1},
		{"1.2.x", "1.2.0", 0},
		{"", "1.0", -1},
		{"1.0", "", 1},
	} {
		if got := Compare(tc.a, tc.b); got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func releaseServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); !strings.HasPrefix(ua, "GoHex/") {
			t.Errorf("User-Agent = %q", ua)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckAvailable(t *testing.T) {
	srv := releaseServer(t, http.StatusOK,
		`{"tag_name":"v0.2.0","html_url":"https://example.com/rel/0.2.0","body":"Highlights"}`)
	res := (&Checker{URL: srv.URL, Client: srv.Client()}).Check(context.Background(), "0.1.0-dev")
	if res.Error != "" {
		t.Fatalf("Error = %q", res.Error)
	}
	if !res.Available || res.Latest != "0.2.0" || res.Current != "0.1.0-dev" {
		t.Fatalf("res = %+v", res)
	}
	if res.URL == "" || res.Notes != "Highlights" {
		t.Errorf("url/notes = %q %q", res.URL, res.Notes)
	}
}

func TestCheckNotAvailable(t *testing.T) {
	for _, latest := range []string{"v0.1.0-dev", "v0.0.9"} {
		srv := releaseServer(t, http.StatusOK, `{"tag_name":"`+latest+`"}`)
		c := &Checker{URL: srv.URL, Client: srv.Client()}
		res := c.Check(context.Background(), "0.1.0-dev")
		if res.Error != "" || res.Available {
			t.Errorf("latest=%s: res = %+v", latest, res)
		}
	}
}

func TestCheckFailures(t *testing.T) {
	// HTTP error status.
	srv := releaseServer(t, http.StatusForbidden, `{}`)
	res := (&Checker{URL: srv.URL, Client: srv.Client()}).Check(context.Background(), "1.0.0")
	if !strings.Contains(res.Error, "HTTP 403") || res.Available {
		t.Errorf("http error: res = %+v", res)
	}

	// Malformed JSON.
	srv = releaseServer(t, http.StatusOK, `not json`)
	res = (&Checker{URL: srv.URL, Client: srv.Client()}).Check(context.Background(), "1.0.0")
	if !strings.Contains(res.Error, "bad response") {
		t.Errorf("bad json: res = %+v", res)
	}

	// Empty tag.
	srv = releaseServer(t, http.StatusOK, `{"tag_name":"  "}`)
	res = (&Checker{URL: srv.URL, Client: srv.Client()}).Check(context.Background(), "1.0.0")
	if !strings.Contains(res.Error, "empty tag_name") {
		t.Errorf("empty tag: res = %+v", res)
	}

	// Oversized body.
	big := `{"tag_name":"v2.0.0","body":"` + strings.Repeat("x", maxBody) + `"}`
	srv = releaseServer(t, http.StatusOK, big)
	res = (&Checker{URL: srv.URL, Client: srv.Client()}).Check(context.Background(), "1.0.0")
	if !strings.Contains(res.Error, "too large") {
		t.Errorf("oversized: res = %+v", res)
	}

	// Unreachable server.
	res = (&Checker{URL: "http://127.0.0.1:1", Client: &http.Client{Timeout: 2 * time.Second}}).
		Check(context.Background(), "1.0.0")
	if res.Error == "" || res.Available {
		t.Errorf("unreachable: res = %+v", res)
	}

	// Context cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res = (&Checker{URL: "http://127.0.0.1:1", Client: &http.Client{}}).Check(ctx, "1.0.0")
	if res.Error == "" {
		t.Errorf("cancelled: res = %+v", res)
	}
}

func TestCheckDefaults(t *testing.T) {
	// Empty URL falls back to the GitHub endpoint; with no network in the
	// test this must fail softly, not panic.
	res := (&Checker{URL: "", Client: &http.Client{Timeout: time.Millisecond}}).
		Check(context.Background(), "1.0.0")
	if res.Current != "1.0.0" {
		t.Errorf("current = %q", res.Current)
	}
	// A nil client is replaced by a sane default rather than panicking.
	res = (&Checker{URL: "http://127.0.0.1:1"}).Check(context.Background(), "1.0.0")
	if res.Error == "" {
		t.Errorf("nil client: res = %+v", res)
	}
}
