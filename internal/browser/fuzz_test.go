package browser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/IshikawaUta/gohex/internal/sqlite"
)

// seedFile loads a checked-in sample as a fuzz seed; missing files are
// skipped so the target still runs in a stripped tree.
func seedFile(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return []byte("seed unavailable")
	}
	return data
}

// FuzzBrowserRead points a Profile at a temporary profile directory whose
// Chrome/Firefox/Safari database files hold arbitrary bytes. Read must not
// panic whatever the files contain: corrupt evidence is the normal case.
//
// Firefox's only JSON surface (the downloads/metaData annotation) lives
// inside places.sqlite, so this target covers it through the Firefox path;
// the standalone Chrome Bookmarks JSON gets its own target below.
func FuzzBrowserRead(f *testing.F) {
	f.Add(seedFile(f, "testdata/chrome/Default/History"))
	f.Add(seedFile(f, "testdata/chrome/Default/Bookmarks"))
	f.Add(seedFile(f, "testdata/firefox/abcd1234.default-release/places.sqlite"))
	f.Add(seedFile(f, "testdata/safari/Library/Safari/History.db"))
	f.Add([]byte{})
	f.Add([]byte("not a database at all"))
	f.Add([]byte("SQLite format 3\x00" + "\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("input too large")
		}
		dir := t.TempDir()
		for _, name := range []string{"History", "Bookmarks", "places.sqlite", "History.db"} {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		_, _ = Read(Profile{Browser: Chrome, Name: "Default", Dir: dir})
		_, _ = Read(Profile{Browser: Firefox, Name: "profile", Dir: dir})
		_, _ = Read(Profile{Browser: Safari, Name: "Safari", Dir: dir})
	})
}

// FuzzChromeHistoryDB fuzzes the Chromium History database parse in
// isolation: open the raw bytes as a database and scan the two tables.
func FuzzChromeHistoryDB(f *testing.F) {
	f.Add(seedFile(f, "testdata/chrome/Default/History"))
	f.Add(seedFile(f, "testdata/chrome_partial/Default/History"))
	f.Add([]byte{})
	f.Add([]byte("SQLite format 3\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("input too large")
		}
		path := filepath.Join(t.TempDir(), "History")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		db, err := sqlite.Open(path)
		if err != nil {
			return
		}
		defer db.Close()
		_, _ = chromeHistory(db)
		_, _ = chromeDownloads(db)
	})
}

// FuzzChromeBookmarks fuzzes the standalone Chromium Bookmarks JSON file.
func FuzzChromeBookmarks(f *testing.F) {
	f.Add(seedFile(f, "testdata/chrome/Default/Bookmarks"))
	f.Add([]byte(`{"roots":{"bookmark_bar":{"children":[{"type":"url","name":"x","url":"http://x/"}],"type":"folder"}}}`))
	f.Add([]byte("{}"))
	f.Add([]byte("{"))
	f.Add([]byte("\xff\xfe\x00not json"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("input too large")
		}
		path := filepath.Join(t.TempDir(), "Bookmarks")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = chromeBookmarks(path)
	})
}
