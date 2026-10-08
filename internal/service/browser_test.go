package service

import (
	"bytes"
	"crypto/sha256"
	stdhex "encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IshikawaUta/gohex/internal/browser"
)

// copyTree duplicates a fixture directory, including the write-ahead log
// beside a database: the log is part of the evidence and reading only the
// main file would give the test a different answer than the product does.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		from := filepath.Join(src, e.Name())
		to := filepath.Join(dst, e.Name())
		if e.IsDir() {
			copyTree(t, from, to)
			continue
		}
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// chromeFixtureHome lays the committed Chrome fixture out where discovery
// expects to find it, so the service tests exercise the real read path.
func chromeFixtureHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	copyTree(t,
		filepath.Join("..", "browser", "testdata", "chrome", "Default"),
		filepath.Join(home, ".config", "google-chrome", "Default"))
	return home
}

func chromeProfile(t *testing.T, app *App) browser.Profile {
	t.Helper()
	home := chromeFixtureHome(t)
	list, err := app.BrowserProfiles(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("discovered %d profiles, want 1: %+v", len(list), list)
	}
	return list[0]
}

func TestBrowserProfiles(t *testing.T) {
	app := newTestApp(t)
	home := t.TempDir()
	// A marker file is enough: listing profiles must not open a database.
	marker := filepath.Join(home, ".config", "chromium", "Default", "History")
	if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	list, err := app.BrowserProfiles(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Browser != browser.Chrome || list[0].Name != "Default" {
		t.Fatalf("profiles = %+v, want one Chrome Default", list)
	}
}

func TestBrowserRead(t *testing.T) {
	app := newTestApp(t)
	p := chromeProfile(t, app)

	r, err := app.BrowserRead(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.History) != 3 || len(r.Downloads) != 3 || len(r.Bookmarks) != 5 {
		t.Fatalf("history=%d downloads=%d bookmarks=%d, want 3/3/5",
			len(r.History), len(r.Downloads), len(r.Bookmarks))
	}
	if len(r.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", r.Warnings)
	}
	if r.Profile.Dir != p.Dir {
		t.Errorf("report profile = %+v, want %+v", r.Profile, p)
	}

	// Reading evidence is an access record.
	logged, err := os.ReadFile(app.cfg.AuditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), `"op":"browser"`) {
		t.Errorf("audit log has no browser entry:\n%s", logged)
	}
}

func TestBrowserReadErrors(t *testing.T) {
	app := newTestApp(t)

	if _, err := app.BrowserRead(browser.Profile{Browser: browser.Chrome, Dir: "  "}); err == nil {
		t.Error("an empty profile directory was accepted")
	}
	missing := browser.Profile{Browser: browser.Chrome, Dir: filepath.Join(t.TempDir(), "nope")}
	if _, err := app.BrowserRead(missing); !errors.Is(err, browser.ErrNotFound) {
		t.Errorf("missing profile error = %v, want ErrNotFound", err)
	}
	// A failed read must still be an audit record, not a silent failure.
	logged, err := os.ReadFile(app.cfg.AuditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), `"result":"error"`) {
		t.Errorf("audit log has no failure entry:\n%s", logged)
	}
}

func TestBrowserExportCSV(t *testing.T) {
	app := newTestApp(t)
	p := chromeProfile(t, app)
	dst := filepath.Join(t.TempDir(), "history.csv")

	res, err := app.BrowserExport(p, "history", "csv", dst)
	if err != nil {
		t.Fatal(err)
	}
	if res.Path != dst || res.Mode != "browser_history" {
		t.Errorf("result = %+v", res)
	}
	out, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	wantHeader := "url,title,visits,typed,lastVisit"
	if lines[0] != wantHeader {
		t.Errorf("header = %q, want %q", lines[0], wantHeader)
	}
	if len(lines) != 4 {
		t.Fatalf("got %d lines, want a header plus 3 rows:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[1], "https://example.com/,") {
		t.Errorf("first row = %q, want the newest visit first", lines[1])
	}
	if !strings.Contains(lines[3], "https://internal.local/doc,,1,0,") {
		t.Errorf("row with no timestamp = %q", lines[3])
	}

	sum := sha256.Sum256(out)
	if res.SHA256 != stdhex.EncodeToString(sum[:]) {
		t.Errorf("SHA256 = %s, want %s", res.SHA256, stdhex.EncodeToString(sum[:]))
	}
	if res.BytesSaved != int64(len(out)) {
		t.Errorf("BytesSaved = %d, want %d", res.BytesSaved, len(out))
	}

	logged, err := os.ReadFile(app.cfg.AuditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), `"op":"browser"`) ||
		!strings.Contains(string(logged), `"export"`) {
		t.Errorf("audit log missing the browser export:\n%s", logged)
	}
}

func TestBrowserExportJSON(t *testing.T) {
	app := newTestApp(t)
	p := chromeProfile(t, app)
	dst := filepath.Join(t.TempDir(), "downloads.json")

	if _, err := app.BrowserExport(p, "downloads", "json", dst); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Source   string          `json:"source"`
		Browser  string          `json:"browser"`
		Profile  string          `json:"profile"`
		Kind     string          `json:"kind"`
		Items    json.RawMessage `json:"items"`
		Exported string          `json:"exportedAt"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("exported JSON does not parse: %v\n%s", err, out)
	}
	if doc.Browser != "Chrome" || doc.Kind != "downloads" || doc.Source != p.Dir {
		t.Errorf("envelope = %+v", doc)
	}
	if doc.Exported == "" {
		t.Error("envelope has no export timestamp")
	}
	var items []map[string]any
	if err := json.Unmarshal(doc.Items, &items); err != nil {
		t.Fatalf("items: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("items = %d, want 3", len(items))
	}
	// The raw state code travels with the readable label, so an unknown
	// value is still recoverable from the report.
	if items[1]["status"] != "complete" {
		t.Errorf("download status = %v", items[1]["status"])
	}
}

func TestBrowserExportBookmarksCSV(t *testing.T) {
	app := newTestApp(t)
	p := chromeProfile(t, app)
	dst := filepath.Join(t.TempDir(), "bookmarks.csv")

	res, err := app.BrowserExport(p, "bookmarks", "csv", dst)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "browser_bookmarks" {
		t.Errorf("mode = %q", res.Mode)
	}
	out, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("path,title,kind,url,added")) {
		t.Errorf("bookmark header missing:\n%s", out)
	}
	if !bytes.Contains(out, []byte("Bookmarks bar / News")) {
		t.Errorf("folder path missing from the export:\n%s", out)
	}
}

func TestBrowserExportErrors(t *testing.T) {
	app := newTestApp(t)
	p := chromeProfile(t, app)
	dst := filepath.Join(t.TempDir(), "out.csv")

	t.Run("empty destination", func(t *testing.T) {
		if _, err := app.BrowserExport(p, "history", "csv", ""); err == nil {
			t.Error("an empty destination was accepted")
		}
	})
	t.Run("unknown format", func(t *testing.T) {
		if _, err := app.BrowserExport(p, "history", "xlsx", dst); err == nil {
			t.Error("an unknown format was accepted")
		}
	})
	t.Run("unknown artefact", func(t *testing.T) {
		if _, err := app.BrowserExport(p, "cookies", "csv", dst); err == nil {
			t.Error("an unknown artefact was accepted")
		}
	})
	t.Run("destination exists", func(t *testing.T) {
		taken := filepath.Join(t.TempDir(), "taken.csv")
		if err := os.WriteFile(taken, []byte("keep"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := app.BrowserExport(p, "history", "csv", taken); err == nil {
			t.Error("an existing destination was overwritten")
		}
		data, err := os.ReadFile(taken)
		if err != nil || string(data) != "keep" {
			t.Errorf("existing file changed: %q (%v)", data, err)
		}
	})
	t.Run("read failure", func(t *testing.T) {
		bad := browser.Profile{Browser: browser.Chrome, Dir: filepath.Join(t.TempDir(), "gone")}
		if _, err := app.BrowserExport(bad, "history", "csv", dst); err == nil {
			t.Error("exporting from a missing profile succeeded")
		}
		if _, err := os.Stat(dst); !os.IsNotExist(err) {
			t.Error("a failed export left a file behind")
		}
	})
}
