package browser

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/IshikawaUta/gohex/internal/sqlite"
)

// Chromium download states, as published in chrome/common/downloads.mojom.
const (
	chromeStateInProgress = 0
	chromeStateComplete   = 1
	chromeStateCancelled  = 2
	chromeStateInterrupt  = 3
)

// chromeStateText renders a Chromium download state. Unknown codes keep an
// empty Status; the raw code stays in DownloadEntry.State either way.
func chromeStateText(state int) string {
	switch state {
	case chromeStateInProgress:
		return "in_progress"
	case chromeStateComplete:
		return "complete"
	case chromeStateCancelled:
		return "cancelled"
	case chromeStateInterrupt:
		return "interrupted"
	}
	return ""
}

// readChromium reads a Chrome, Chromium, Edge or Brave profile. All four
// share the same on-disk layout, so one reader covers them.
func readChromium(p Profile) (Report, error) {
	r := Report{Profile: p}
	db, err := openRead(filepath.Join(p.Dir, "History"))
	if err != nil {
		return r, err
	}
	defer db.Close()

	if r.History, err = chromeHistory(db); err != nil {
		if err := r.absorb(err); err != nil {
			return r, err
		}
	}
	if r.Downloads, err = chromeDownloads(db); err != nil {
		if err := r.absorb(err); err != nil {
			return r, err
		}
	}
	r.takeWarnings(db)

	bookmarks, err := chromeBookmarks(filepath.Join(p.Dir, "Bookmarks"))
	switch {
	case errors.Is(err, ErrNotFound):
		// A profile without a bookmarks file simply has none.
	case err != nil:
		r.Warnings = append(r.Warnings, err.Error())
	default:
		r.Bookmarks = bookmarks
	}

	sortHistory(r.History)
	sortDownloads(r.Downloads)
	sortBookmarks(r.Bookmarks)
	return r, nil
}

// chromeHistory reads the urls table: one row per distinct URL with the
// browser's own aggregate counters.
func chromeHistory(db *sqlite.DB) ([]HistoryEntry, error) {
	t, err := tableFor(db, "urls")
	if err != nil {
		return nil, err
	}
	var out []HistoryEntry
	err = t.Scan(func(r sqlite.Row) error {
		e := HistoryEntry{
			URL:       rowText(&r, "url"),
			Title:     rowText(&r, "title"),
			Visits:    rowInt(&r, "visit_count"),
			Typed:     rowInt(&r, "typed_count"),
			LastVisit: chromeTime(rowInt(&r, "last_visit_time")),
		}
		if e.URL == "" {
			return nil // a history entry without a URL carries nothing
		}
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("browser: history: %w", err)
	}
	return out, nil
}

// chromeDownloads reads the downloads table and, when present, the first URL
// of each download chain. The chains table only enriches the source URL: if
// it is missing or unreadable the download is still reported with an empty
// URL rather than dropped.
func chromeDownloads(db *sqlite.DB) ([]DownloadEntry, error) {
	t, err := tableFor(db, "downloads")
	if err != nil {
		return nil, err
	}

	sources := map[int64]string{}
	if chains, err := db.Table("downloads_url_chains"); err == nil {
		_ = chains.Scan(func(r sqlite.Row) error {
			if rowInt(&r, "chain_index") != 0 {
				return nil // only the first link of the chain is the source
			}
			sources[rowInt(&r, "download_id")] = rowText(&r, "url")
			return nil
		})
	}

	var out []DownloadEntry
	err = t.Scan(func(r sqlite.Row) error {
		id := rowInt(&r, "id")
		state := -1
		if rowPresent(&r, "state") {
			state = int(rowInt(&r, "state"))
		}
		out = append(out, DownloadEntry{
			URL:      sources[id],
			Target:   firstNonEmpty(rowText(&r, "current_path"), rowText(&r, "target_path")),
			Start:    chromeTime(rowInt(&r, "start_time")),
			Received: rowInt(&r, "received_bytes"),
			Total:    rowInt(&r, "total_bytes"),
			State:    state,
			Status:   chromeStateText(state),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("browser: downloads: %w", err)
	}
	return out, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// chromiumTime is a Chromium JSON timestamp: a decimal number of
// microseconds since 1601-01-01, usually quoted as a string but written
// unquoted by some forks.
type chromiumTime string

func (t *chromiumTime) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if len(trimmed) > 1 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
		trimmed = trimmed[1 : len(trimmed)-1]
	}
	*t = chromiumTime(trimmed)
	return nil
}

// chromeNode mirrors the recursive node type of Chromium's Bookmarks file.
type chromeNode struct {
	Type     string       `json:"type"`
	Name     string       `json:"name"`
	URL      string       `json:"url"`
	Date     chromiumTime `json:"date_added"`
	Children []chromeNode `json:"children"`
}

// chromeRootNames maps the fixed root keys Chromium writes to the labels its
// own UI shows, so exported paths read the way the browser presents them.
var chromeRootNames = map[string]string{
	"bookmark_bar": "Bookmarks bar",
	"other":        "Other bookmarks",
	"synced":       "Mobile bookmarks",
	"managed":      "Managed bookmarks",
}

// chromeBookmarks parses the standalone Bookmarks JSON file. It is not a
// database, so this is a plain structural walk of the tree.
func chromeBookmarks(path string) ([]BookmarkEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		return nil, fmt.Errorf("browser: bookmarks: %w", err)
	}
	var doc struct {
		Roots map[string]chromeNode `json:"roots"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("browser: bookmarks: %w", err)
	}
	if len(doc.Roots) == 0 {
		return nil, nil
	}

	// JSON objects have no order; sort the roots so output is reproducible.
	keys := make([]string, 0, len(doc.Roots))
	for k := range doc.Roots {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []BookmarkEntry
	var walk func(n chromeNode, path string)
	walk = func(n chromeNode, path string) {
		kind := BookmarkURL
		url := n.URL
		if n.Type == "folder" || (n.Type == "" && url == "") {
			kind = BookmarkFolder
			url = ""
		}
		out = append(out, BookmarkEntry{
			URL:   url,
			Title: n.Name,
			Path:  path,
			Kind:  kind,
			Added: chromeTime(parseDecimal(string(n.Date))),
		})
		childPath := path
		if path != "" {
			childPath = path + " / " + n.Name
		} else {
			childPath = n.Name
		}
		for _, c := range n.Children {
			walk(c, childPath)
		}
	}
	for _, k := range keys {
		root := doc.Roots[k]
		name := chromeRootNames[k]
		if name == "" {
			name = k
		}
		// Present the root itself under its label, then walk its children
		// with the label as their folder path.
		out = append(out, BookmarkEntry{
			Title: name,
			Kind:  BookmarkFolder,
			Added: chromeTime(parseDecimal(string(root.Date))),
		})
		for _, c := range root.Children {
			walk(c, name)
		}
	}
	return out, nil
}

// parseDecimal reads an unsigned decimal integer, returning 0 for anything
// else rather than failing the whole file over one malformed timestamp.
func parseDecimal(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	var v int64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0
		}
		v = v*10 + int64(s[i]-'0')
	}
	return v
}
