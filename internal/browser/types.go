// Package browser reads browsing artefacts — history, downloads and
// bookmarks — out of the databases Chrome, Firefox and Safari keep on disk.
//
// The reader is deliberately narrow: it reconstructs what was visited, from
// what, when and what was downloaded, and nothing else. Credentials, cookies,
// autofill and form data are out of scope and are never queried, so this
// package cannot be turned into a password stealer.
//
// Every database is opened read-only and, where the file is in WAL mode,
// through internal/sqlite, which merges committed log frames without touching
// the file. Nothing here ever writes to, checkpoints or repairs evidence.
package browser

import (
	"errors"
	"time"
)

// Browser identifies which application a profile belongs to. It is a string
// type because the value crosses the JSON boundary to the front-end: an iota
// would force the UI to mirror the constant order just to label a row.
type Browser string

const (
	Chrome  Browser = "Chrome"
	Firefox Browser = "Firefox"
	Safari  Browser = "Safari"
)

// String returns the browser's display name, or "Unknown" for a value this
// build has never heard of.
func (b Browser) String() string {
	switch b {
	case Chrome, Firefox, Safari:
		return string(b)
	}
	return "Unknown"
}

// Profile is one browser profile found on disk.
type Profile struct {
	Browser Browser `json:"browser"`
	// Name is the profile directory name as the browser writes it, for
	// example "Default" or "Profile 1" for Chromium and the profile folder
	// name for Firefox.
	Name string `json:"name"`
	// Dir is the directory that holds the profile's databases.
	Dir string `json:"dir"`
}

// HistoryEntry is one URL a profile has visited.
type HistoryEntry struct {
	URL string `json:"url"`
	// Title is the page title the browser last recorded; empty when the
	// database never stored one.
	Title string `json:"title"`
	// Visits is the browser's own aggregate visit count, not a count of
	// rows in this result.
	Visits int64 `json:"visits"`
	// LastVisit is the most recent recorded visit, or the zero time when
	// the browser stored no timestamp.
	LastVisit time.Time `json:"lastVisit"`
	// Typed is how often the URL was entered by hand rather than followed
	// as a link. Browsers that do not track this report zero.
	Typed int64 `json:"typed"`
}

// DownloadEntry is one file a profile downloaded.
type DownloadEntry struct {
	// URL is the source the file came from.
	URL string `json:"url"`
	// Target is the destination path as the browser recorded it. Chromium
	// stores an absolute path; Firefox stores a file:// URI.
	Target string `json:"target"`
	// Start is when the download began, or the zero time if unknown.
	Start time.Time `json:"start"`
	// End is when the download finished, failed or was cancelled. Only
	// Firefox persists it; Chromium has no such column, so it stays zero.
	End time.Time `json:"end"`
	// Received and Total are byte counts; both are zero when the browser
	// did not record them, which is the case for Received in Firefox —
	// only the final size is kept there.
	Received int64 `json:"receivedBytes"`
	Total    int64 `json:"totalBytes"`
	// State is the raw browser-specific status code. The mapping differs
	// per browser and is preserved verbatim: overwriting it with a guess
	// would lose evidence. -1 means the column was absent.
	State int `json:"state"`
	// Status is a readable form of State for browsers whose codes this
	// package documents. It is empty when there is no known mapping.
	Status string `json:"status"`
}

// BookmarkKind distinguishes a bookmark from the folder that contains it.
// Like Browser it is a string so the value survives the trip to the UI.
type BookmarkKind string

const (
	BookmarkURL    BookmarkKind = "url"
	BookmarkFolder BookmarkKind = "folder"
)

// String returns the kind as the UI and the CSV export spell it.
func (k BookmarkKind) String() string { return string(k) }

// BookmarkEntry is one node from a profile's bookmark tree.
type BookmarkEntry struct {
	URL   string `json:"url"`
	Title string `json:"title"`
	// Path is the folder path from the tree root, using " / " as the
	// separator, for example "Bookmarks bar / News".
	Path string       `json:"path"`
	Kind BookmarkKind `json:"kind"`
	// Added is when the node was created, or the zero time if unknown.
	Added time.Time `json:"added"`
}

// Report is everything read from a single profile. The slices are nil when
// the profile does not store that artefact at all (for example Safari has no
// download database and Firefox stores bookmarks inside places.sqlite).
type Report struct {
	Profile   Profile         `json:"profile"`
	History   []HistoryEntry  `json:"history"`
	Downloads []DownloadEntry `json:"downloads"`
	Bookmarks []BookmarkEntry `json:"bookmarks"`
	// Warnings explain anything that was skipped or could not be trusted,
	// such as an invalid WAL or a table this reader does not understand.
	Warnings []string `json:"warnings"`
}

var (
	// ErrNotFound is returned when a profile or one of its databases does
	// not exist.
	ErrNotFound = errors.New("browser: database not found")
	// ErrUnsupported is returned for artefacts this reader deliberately
	// does not parse, such as Safari's binary-plist bookmarks.
	ErrUnsupported = errors.New("browser: artefact not supported")
)

// The ethics notice required by docs/legal.md the first time the browser
// view is opened lives in the translation catalog under
// "dialog.ethics.browser", so that it is localised and its English/Indonesian
// parity is covered by the catalog tests like every other dialog string.
