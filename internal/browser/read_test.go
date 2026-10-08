package browser

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(parts ...string) string {
	return filepath.Join(append([]string{"testdata"}, parts...)...)
}

// utc builds a UTC instant the fixtures are stamped with.
func utc(year int, month time.Month, day, hour, min, sec int) time.Time {
	return time.Date(year, month, day, hour, min, sec, 0, time.UTC)
}

func mustRead(t *testing.T, p Profile) Report {
	t.Helper()
	r, err := Read(p)
	if err != nil {
		t.Fatalf("Read(%+v): %v", p, err)
	}
	if len(r.Warnings) != 0 {
		t.Errorf("Read(%+v) reported warnings: %v", p, r.Warnings)
	}
	if r.Profile != p {
		t.Errorf("report profile = %+v, want %+v", r.Profile, p)
	}
	return r
}

func TestReadChromium(t *testing.T) {
	p := Profile{Browser: Chrome, Name: "Default", Dir: fixture("chrome", "Default")}
	r := mustRead(t, p)

	// History, newest first. The Chrome file is read with an uncheckpointed
	// write-ahead log, so this also proves the reader merges committed
	// frames instead of seeing an empty page 1.
	if len(r.History) != 3 {
		t.Fatalf("history has %d entries: %+v", len(r.History), r.History)
	}
	wantHistory := []struct {
		url, title string
		visits     int64
		typed      int64
		last       time.Time
	}{
		{"https://example.com/", "Example Domain", 5, 2, utc(2024, 1, 15, 12, 0, 0)},
		{"https://go.dev/", "Go", 3, 1, utc(2024, 1, 15, 11, 0, 0)},
		{"https://internal.local/doc", "", 1, 0, time.Time{}},
	}
	for i, w := range wantHistory {
		got := r.History[i]
		if got.URL != w.url || got.Title != w.title || got.Visits != w.visits ||
			got.Typed != w.typed || !got.LastVisit.Equal(w.last) {
			t.Errorf("history[%d] = {URL:%q Title:%q Visits:%d Typed:%d LastVisit:%v}, want %+v",
				i, got.URL, got.Title, got.Visits, got.Typed, got.LastVisit, w)
		}
	}

	if len(r.Downloads) != 3 {
		t.Fatalf("downloads has %d entries: %+v", len(r.Downloads), r.Downloads)
	}
	// Two downloads share a start time, so the URL breaks the tie; the
	// cancelled one started a minute earlier and sorts last.
	wantURLs := []string{
		"https://cdn.example.com/partial.zip",
		"https://example.com/report.pdf",
		"https://example.com/cancelled.bin",
	}
	for i, w := range wantURLs {
		if r.Downloads[i].URL != w {
			t.Errorf("downloads[%d].URL = %q, want %q", i, r.Downloads[i].URL, w)
		}
	}
	if d := r.Downloads[1]; d.Target != "/home/analyst/Downloads/report.pdf" ||
		d.Received != 1024 || d.Total != 2048 || d.State != chromeStateComplete ||
		d.Status != "complete" || !d.End.IsZero() {
		t.Errorf("complete download = %+v", d)
	}
	if d := r.Downloads[0]; d.State != chromeStateInProgress || d.Status != "in_progress" ||
		d.Target != "/tmp/partial.zip" || d.Received != 100 || d.Total != 0 {
		t.Errorf("in-progress download = %+v", d)
	}
	if d := r.Downloads[2]; d.Status != "cancelled" || d.Total != 4096 {
		t.Errorf("cancelled download = %+v", d)
	}
	// The second link of a redirect chain must never be reported as the
	// source of the download.
	for _, d := range r.Downloads {
		if d.URL == "https://mirror.example.com/report.pdf" {
			t.Error("a redirected chain link was reported as the download source")
		}
	}

	wantBookmarks := []BookmarkEntry{
		{Title: "Bookmarks bar", Path: "", Kind: BookmarkFolder, Added: utc(2024, 1, 15, 12, 0, 0)},
		{Title: "Other bookmarks", Path: "", Kind: BookmarkFolder},
		{URL: "https://example.com/", Title: "Example", Path: "Bookmarks bar", Kind: BookmarkURL, Added: utc(2024, 1, 15, 12, 0, 0)},
		{Title: "News", Path: "Bookmarks bar", Kind: BookmarkFolder, Added: utc(2024, 1, 15, 12, 0, 0)},
		{URL: "https://go.dev/blog/", Title: "Go Blog", Path: "Bookmarks bar / News", Kind: BookmarkURL, Added: utc(2024, 1, 15, 12, 0, 0)},
	}
	if len(r.Bookmarks) != len(wantBookmarks) {
		t.Fatalf("bookmarks has %d entries: %+v", len(r.Bookmarks), r.Bookmarks)
	}
	for i, w := range wantBookmarks {
		got := r.Bookmarks[i]
		if got != w {
			t.Errorf("bookmarks[%d] = %+v, want %+v", i, got, w)
		}
	}
}

// TestReadChromiumPartialSchema covers a file whose tables have drifted: the
// downloads table is gone entirely, and there is no bookmarks file. The
// history must still come back, with the reason recorded rather than lost.
func TestReadChromiumPartialSchema(t *testing.T) {
	p := Profile{Browser: Chrome, Name: "Default", Dir: fixture("chrome_partial", "Default")}
	r, err := Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(r.History) != 1 || r.History[0].URL != "https://only.example/" {
		t.Fatalf("history = %+v, want the one row", r.History)
	}
	if r.History[0].LastVisit.Equal(time.Time{}) {
		t.Error("last visit was not read")
	}
	if len(r.Downloads) != 0 {
		t.Errorf("downloads = %+v, want none", r.Downloads)
	}
	if len(r.Bookmarks) != 0 {
		t.Errorf("bookmarks = %+v, want none", r.Bookmarks)
	}
	if len(r.Warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly the missing-table note", r.Warnings)
	}
	if !strings.Contains(r.Warnings[0], "downloads") {
		t.Errorf("warning %q does not name the missing table", r.Warnings[0])
	}
}

func TestReadFirefox(t *testing.T) {
	p := Profile{Browser: Firefox, Name: "abcd1234.default-release",
		Dir: fixture("firefox", "abcd1234.default-release")}
	r := mustRead(t, p)

	wantHistory := []struct {
		url, title string
		visits     int64
		typed      int64
		last       time.Time
	}{
		{"https://dl.example.com/a.zip", "a.zip", 1, 0, utc(2024, 1, 15, 12, 0, 0)},
		{"https://dl.example.com/b.7z", "b.7z", 1, 0, utc(2024, 1, 15, 12, 0, 0)},
		{"https://mozilla.org/", "Mozilla", 4, 1, utc(2024, 1, 15, 12, 0, 0)},
		{"https://example.org/", "", 1, 0, time.Time{}},
	}
	if len(r.History) != len(wantHistory) {
		t.Fatalf("history has %d entries: %+v", len(r.History), r.History)
	}
	for i, w := range wantHistory {
		got := r.History[i]
		if got.URL != w.url || got.Title != w.title || got.Visits != w.visits ||
			got.Typed != w.typed || !got.LastVisit.Equal(w.last) {
			t.Errorf("history[%d] = %+v, want %+v", i, got, w)
		}
	}

	if len(r.Downloads) != 2 {
		t.Fatalf("downloads has %d entries: %+v", len(r.Downloads), r.Downloads)
	}
	done := r.Downloads[0]
	if done.Target != "file:///home/analyst/Downloads/a.zip" || done.State != ffStateFinished ||
		done.Status != "complete" || done.Total != 1024 || done.Received != 0 {
		t.Errorf("finished download = %+v", done)
	}
	if want := utc(2024, 1, 15, 12, 1, 0); !done.End.Equal(want) {
		t.Errorf("finished download ended at %v, want %v", done.End, want)
	}
	failed := r.Downloads[1]
	if failed.State != ffStateFailed || failed.Status != "failed" || failed.Total != 0 {
		t.Errorf("failed download = %+v", failed)
	}
	if want := utc(2024, 1, 15, 12, 0, 5); !failed.End.Equal(want) {
		t.Errorf("failed download ended at %v, want %v", failed.End, want)
	}
	// The bookmarkSync annotation is not a download.
	for _, d := range r.Downloads {
		if d.Target == "sync-token" {
			t.Error("an unrelated annotation was read as a download")
		}
	}

	wantBookmarks := []BookmarkEntry{
		{Title: "Bookmarks Menu", Path: "", Kind: BookmarkFolder, Added: utc(2024, 1, 15, 12, 0, 0)},
		{Title: "root", Path: "", Kind: BookmarkFolder, Added: utc(2024, 1, 15, 12, 0, 0)},
		{URL: "https://example.org/", Title: "Example", Path: "Bookmarks Menu", Kind: BookmarkURL, Added: utc(2024, 1, 15, 12, 0, 0)},
		{Title: "News", Path: "Bookmarks Menu", Kind: BookmarkFolder, Added: utc(2024, 1, 15, 12, 0, 0)},
		{URL: "https://mozilla.org/", Title: "Mozilla", Path: "Bookmarks Menu / News", Kind: BookmarkURL, Added: utc(2024, 1, 15, 12, 0, 0)},
	}
	if len(r.Bookmarks) != len(wantBookmarks) {
		t.Fatalf("bookmarks has %d entries: %+v", len(r.Bookmarks), r.Bookmarks)
	}
	for i, w := range wantBookmarks {
		if r.Bookmarks[i] != w {
			t.Errorf("bookmarks[%d] = %+v, want %+v", i, r.Bookmarks[i], w)
		}
	}
}

func TestReadSafari(t *testing.T) {
	p := Profile{Browser: Safari, Name: "Safari", Dir: fixture("safari", "Library", "Safari")}
	r := mustRead(t, p)

	if len(r.History) != 3 {
		t.Fatalf("history has %d entries: %+v", len(r.History), r.History)
	}
	apple := r.History[0]
	if apple.URL != "https://apple.com/" || apple.Title != "Apple" || apple.Visits != 2 {
		t.Errorf("apple entry = %+v", apple)
	}
	if !apple.LastVisit.Equal(utc(2024, 1, 15, 12, 0, 0)) {
		t.Errorf("apple last visit = %v, want 12:00:00Z", apple.LastVisit)
	}
	// The newest visit to Hacker News carries no title; the earlier one does
	// and must survive instead of being blanked out.
	hn := r.History[1]
	if hn.URL != "https://news.ycombinator.com/" || hn.Title != "Hacker News" {
		t.Errorf("hacker news entry = %+v", hn)
	}
	if want := utc(2024, 1, 15, 11, 43, 20); !hn.LastVisit.Equal(want) {
		t.Errorf("hacker news last visit = %v, want %v", hn.LastVisit, want)
	}
	// An item with no visits at all still appears, with an unset time.
	empty := r.History[2]
	if empty.URL != "https://empty.example/" || !empty.LastVisit.IsZero() || empty.Visits != 0 {
		t.Errorf("empty entry = %+v", empty)
	}

	// Safari keeps neither downloads nor parseable bookmarks in History.db.
	if r.Downloads != nil || r.Bookmarks != nil {
		t.Errorf("Safari reported downloads=%v bookmarks=%v, want none", r.Downloads, r.Bookmarks)
	}
}

func TestReadErrors(t *testing.T) {
	if _, err := Read(Profile{Browser: Browser("Edge"), Dir: "testdata"}); err == nil {
		t.Error("an unknown browser was accepted")
	}
	missing := filepath.Join(t.TempDir(), "nowhere")
	_, err := Read(Profile{Browser: Chrome, Dir: missing})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("missing profile error = %v, want ErrNotFound", err)
	}
	// A directory that exists but holds no databases is also ErrNotFound,
	// not a crash.
	if _, err := Read(Profile{Browser: Firefox, Dir: t.TempDir()}); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty profile error = %v, want ErrNotFound", err)
	}
}

func TestReportAbsorb(t *testing.T) {
	var r Report
	if err := r.absorb(nil); err != nil {
		t.Errorf("absorb(nil) = %v, want nil", err)
	}
	if err := r.absorb(fmt.Errorf("while reading %w", errTableMissing)); err != nil {
		t.Errorf("a missing table must not propagate: %v", err)
	}
	if len(r.Warnings) != 1 {
		t.Fatalf("warnings = %v, want one", r.Warnings)
	}
	if err := r.absorb(errors.New("disk on fire")); err == nil {
		t.Error("a real failure must propagate to the caller")
	}
	if len(r.Warnings) != 1 {
		t.Errorf("a propagated error leaked into Warnings: %v", r.Warnings)
	}
}

// TestFixturesAreReadOnly pins the promise in the package documentation: a
// read must leave every byte of the evidence untouched. The SHA of the file
// is taken before and after so a stray write, checkpoint or repair shows up.
func TestFixturesAreReadOnly(t *testing.T) {
	for _, rel := range [][]string{
		{"chrome", "Default", "History"},
		{"chrome", "Default", "History-wal"},
		{"chrome_partial", "Default", "History"},
		{"firefox", "abcd1234.default-release", "places.sqlite"},
		{"safari", "Library", "Safari", "History.db"},
	} {
		path := fixture(rel...)
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		p := Profile{Browser: Chrome, Name: "x", Dir: filepath.Dir(path)}
		switch {
		case strings.Contains(path, "firefox"):
			p.Browser = Firefox
		case strings.Contains(path, "safari"):
			p.Browser = Safari
		}
		if _, err := Read(p); err != nil {
			t.Fatalf("Read(%s): %v", path, err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(after) != len(data) || string(after) != string(data) {
			t.Errorf("%s changed while it was being read", path)
			continue
		}
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !st.ModTime().Equal(before.ModTime()) {
			t.Errorf("%s modification time moved", path)
		}
	}
}
