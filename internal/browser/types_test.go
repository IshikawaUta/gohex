package browser

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBrowserJSON(t *testing.T) {
	for _, tc := range []struct {
		in   Browser
		want string
	}{
		{Chrome, `"Chrome"`},
		{Firefox, `"Firefox"`},
		{Safari, `"Safari"`},
	} {
		got, err := json.Marshal(tc.in)
		if err != nil {
			t.Fatalf("marshal %v: %v", tc.in, err)
		}
		if string(got) != tc.want {
			t.Errorf("marshal %v = %s, want %s", tc.in, got, tc.want)
		}
		var back Browser
		if err := json.Unmarshal(got, &back); err != nil {
			t.Fatalf("unmarshal %s: %v", got, err)
		}
		if back != tc.in {
			t.Errorf("round trip %v = %v", tc.in, back)
		}
	}

	// A number is not a browser name. The decoder accepts any string — the
	// read path is where an unknown one is rejected — so only the type
	// mismatch is asserted here.
	var b Browser
	if err := json.Unmarshal([]byte(`2`), &b); err == nil {
		t.Error("accepted a bare number as a browser")
	}
	if got := Browser("Edge").String(); got != "Unknown" {
		t.Errorf("unknown browser renders as %q, want Unknown", got)
	}
}

func TestBookmarkKindJSON(t *testing.T) {
	for _, tc := range []struct {
		in   BookmarkKind
		want string
	}{
		{BookmarkFolder, `"folder"`},
		{BookmarkURL, `"url"`},
	} {
		got, err := json.Marshal(tc.in)
		if err != nil {
			t.Fatalf("marshal %v: %v", tc.in, err)
		}
		if string(got) != tc.want {
			t.Errorf("marshal %v = %s, want %s", tc.in, got, tc.want)
		}
		var back BookmarkKind
		if err := json.Unmarshal(got, &back); err != nil {
			t.Fatalf("unmarshal %s: %v", got, err)
		}
		if back != tc.in {
			t.Errorf("round trip %v = %v", tc.in, back)
		}
	}
	var k BookmarkKind
	if err := json.Unmarshal([]byte(`1`), &k); err == nil {
		t.Error("accepted a bare number as a bookmark kind")
	}
	if BookmarkURL.String() != "url" || BookmarkFolder.String() != "folder" {
		t.Errorf("kind labels = %q / %q", BookmarkURL, BookmarkFolder)
	}
}

// TestReportWireFormat pins the JSON field names the front-end compiles
// against. Renaming one silently would show up as an empty column in the GUI
// rather than as a build failure, so the contract is checked here.
func TestReportWireFormat(t *testing.T) {
	r := Report{
		Profile: Profile{Browser: Chrome, Name: "Default", Dir: "/home/u/.config/chrome"},
		History: []HistoryEntry{{
			URL:       "https://example.com/",
			Title:     "Example",
			Visits:    2,
			Typed:     1,
			LastVisit: time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC),
		}},
		Downloads: []DownloadEntry{{
			URL: "https://example.com/f.zip", Target: "/tmp/f.zip", State: 1,
			Status: "complete", Received: 1, Total: 2,
		}},
		Bookmarks: []BookmarkEntry{{
			URL: "https://example.com/", Title: "Example", Path: "Bar",
			Kind: BookmarkURL, Added: time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC),
		}},
		Warnings: []string{"something was skipped"},
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	want := []string{
		`"browser":"Chrome"`, `"name":"Default"`, `"dir":"/home/u/.config/chrome"`,
		`"history"`, `"downloads"`, `"bookmarks"`, `"warnings"`,
		`"url":"https://example.com/"`, `"title":"Example"`, `"visits":2`,
		`"typed":1`, `"lastVisit":"2024-01-15T12:00:00Z"`,
		`"target":"/tmp/f.zip"`, `"receivedBytes":1`, `"totalBytes":2`,
		`"state":1`, `"status":"complete"`, `"start"`, `"end"`,
		`"path":"Bar"`, `"kind":"url"`, `"added"`,
		`"something was skipped"`,
	}
	for _, w := range want {
		if !strings.Contains(s, w) {
			t.Errorf("wire format lost %s:\n%s", w, s)
		}
	}
	// PascalCase field names would mean a tag was dropped.
	for _, bad := range []string{`"URL"`, `"Title"`, `"Visits"`, `"LastVisit"`, `"Kind"`} {
		if strings.Contains(s, bad) {
			t.Errorf("wire format leaked %s:\n%s", bad, s)
		}
	}

	var back Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if back.Profile != r.Profile || len(back.History) != 1 ||
		back.History[0].URL != r.History[0].URL ||
		!back.History[0].LastVisit.Equal(r.History[0].LastVisit) ||
		back.Bookmarks[0].Kind != BookmarkURL ||
		back.Downloads[0].Status != "complete" {
		t.Errorf("round trip lost data: %+v", back)
	}
}
