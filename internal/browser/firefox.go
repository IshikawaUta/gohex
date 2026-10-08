package browser

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/IshikawaUta/gohex/internal/sqlite"
)

// Firefox download states written into the downloads/metaData annotation.
// The values come from toolkit/components/downloads/DownloadHistory.sys.mjs;
// they are not the same numbers Chromium uses, which is why DownloadEntry
// keeps the raw code alongside the label.
const (
	ffStateFinished        = 1
	ffStateFailed          = 2
	ffStateCancelled       = 3
	ffStatePaused          = 4
	ffStateBlockedParental = 6
	ffStateBlocked         = 8
)

// Annotation names Firefox attaches to a place to describe a download.
const (
	ffAnnoDestination = "downloads/destinationFileURI"
	ffAnnoMetaData    = "downloads/metaData"
)

func firefoxStateText(state int) string {
	switch state {
	case ffStateFinished:
		return "complete"
	case ffStateFailed:
		return "failed"
	case ffStateCancelled:
		return "cancelled"
	case ffStatePaused:
		return "paused"
	case ffStateBlockedParental:
		return "blocked_parental"
	case ffStateBlocked:
		return "blocked"
	}
	return ""
}

// readFirefox reads one Firefox profile. History, downloads and bookmarks
// all live in places.sqlite, so the file is opened once.
func readFirefox(p Profile) (Report, error) {
	r := Report{Profile: p}
	db, err := openRead(filepath.Join(p.Dir, "places.sqlite"))
	if err != nil {
		return r, err
	}
	defer db.Close()

	for _, step := range []struct {
		name string
		run  func(*sqlite.DB) error
	}{
		{"history", func(db *sqlite.DB) error {
			var err error
			r.History, err = firefoxHistory(db)
			return err
		}},
		{"downloads", func(db *sqlite.DB) error {
			var err error
			r.Downloads, err = firefoxDownloads(db)
			return err
		}},
		{"bookmarks", func(db *sqlite.DB) error {
			var err error
			r.Bookmarks, err = firefoxBookmarks(db)
			return err
		}},
	} {
		if err := step.run(db); err != nil {
			if err := r.absorb(err); err != nil {
				return r, fmt.Errorf("browser: firefox %s: %w", step.name, err)
			}
		}
	}
	r.takeWarnings(db)

	sortHistory(r.History)
	sortDownloads(r.Downloads)
	sortBookmarks(r.Bookmarks)
	return r, nil
}

// firefoxHistory reads moz_places, which holds one row per distinct URL
// with the same aggregate counters Chromium keeps in urls.
func firefoxHistory(db *sqlite.DB) ([]HistoryEntry, error) {
	t, err := tableFor(db, "moz_places")
	if err != nil {
		return nil, err
	}
	var out []HistoryEntry
	err = t.Scan(func(r sqlite.Row) error {
		e := HistoryEntry{
			URL:       rowText(&r, "url"),
			Title:     rowText(&r, "title"),
			Visits:    rowInt(&r, "visit_count"),
			Typed:     rowInt(&r, "typed"),
			LastVisit: firefoxTime(rowInt(&r, "last_visit_date")),
		}
		if e.URL == "" {
			return nil
		}
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("browser: history: %w", err)
	}
	return out, nil
}

// ffMeta is the JSON blob Firefox stores in downloads/metaData. Every field
// is a float because the browser writes integers but a fork may not, and one
// unexpected shape must not discard the rest of the annotation.
type ffMeta struct {
	State    float64 `json:"state"`
	End      float64 `json:"endTime"` // milliseconds since the Unix epoch
	FileSize float64 `json:"fileSize"`
}

// firefoxDownloads reconstructs downloads from annotations. Firefox keeps no
// downloads table: the destination URI and the metadata JSON are two
// annotations hanging off the same place, and a download only exists where
// both conceptually meet.
func firefoxDownloads(db *sqlite.DB) ([]DownloadEntry, error) {
	attrTable, err := tableFor(db, "moz_anno_attributes")
	if err != nil {
		return nil, err
	}
	annoTable, err := tableFor(db, "moz_annos")
	if err != nil {
		return nil, err
	}
	placeTable, err := tableFor(db, "moz_places")
	if err != nil {
		return nil, err
	}

	wanted := map[int64]string{}
	if err := attrTable.Scan(func(r sqlite.Row) error {
		name := rowText(&r, "name")
		if name == ffAnnoDestination || name == ffAnnoMetaData {
			wanted[rowInt(&r, "id")] = name
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("browser: downloads: %w", err)
	}
	if len(wanted) == 0 {
		return nil, nil
	}

	type destination struct {
		place  int64
		target string
		added  int64
	}
	var dests []destination
	meta := map[int64]string{}
	if err := annoTable.Scan(func(r sqlite.Row) error {
		name, ok := wanted[rowInt(&r, "anno_attribute_id")]
		if !ok {
			return nil
		}
		place := rowInt(&r, "place_id")
		switch name {
		case ffAnnoDestination:
			dests = append(dests, destination{
				place:  place,
				target: rowText(&r, "content"),
				added:  rowIntAny(&r, "dateAdded", "date_added"),
			})
		case ffAnnoMetaData:
			meta[place] = rowText(&r, "content")
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("browser: downloads: %w", err)
	}
	if len(dests) == 0 {
		return nil, nil
	}

	urls := map[int64]string{}
	if err := placeTable.Scan(func(r sqlite.Row) error {
		urls[rowInt(&r, "id")] = rowText(&r, "url")
		return nil
	}); err != nil {
		return nil, fmt.Errorf("browser: downloads: %w", err)
	}

	out := make([]DownloadEntry, 0, len(dests))
	for _, d := range dests {
		e := DownloadEntry{
			URL:    urls[d.place],
			Target: d.target, // a file:// URI, exactly as Firefox recorded it
			Start:  firefoxTime(d.added),
			State:  -1,
		}
		if raw := meta[d.place]; raw != "" {
			var m ffMeta
			if err := json.Unmarshal([]byte(raw), &m); err == nil {
				e.State = int(m.State)
				e.Status = firefoxStateText(e.State)
				e.Total = int64(m.FileSize)
				// endTime is milliseconds; convert without losing the
				// sub-second part to integer division of a negative value.
				if m.End > 0 {
					ms := int64(m.End)
					e.End = firefoxTime(ms * 1000)
				}
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// firefoxBookmarks walks moz_bookmarks. Folder paths are reconstructed from
// the parent chain because Firefox stores no path of its own.
func firefoxBookmarks(db *sqlite.DB) ([]BookmarkEntry, error) {
	t, err := tableFor(db, "moz_bookmarks")
	if err != nil {
		return nil, err
	}
	placeTable, err := tableFor(db, "moz_places")
	if err != nil {
		return nil, err
	}

	urls := map[int64]string{}
	if err := placeTable.Scan(func(r sqlite.Row) error {
		urls[rowInt(&r, "id")] = rowText(&r, "url")
		return nil
	}); err != nil {
		return nil, fmt.Errorf("browser: bookmarks: %w", err)
	}

	var nodes []*ffNode
	byID := map[int64]*ffNode{}
	if err := t.Scan(func(r sqlite.Row) error {
		id, parent := rowInt(&r, "id"), rowInt(&r, "parent")
		if id <= 0 {
			return nil
		}
		// Firefox's type column: 1 is a place (a bookmarked URL), 2 is a
		// folder. Anything else is a tag or a container this reader does
		// not report.
		kind := BookmarkFolder
		var url string
		switch rowInt(&r, "type") {
		case 1:
			kind = BookmarkURL
			url = urls[rowInt(&r, "fk")]
			if url == "" {
				return nil // dangling or tag placeholder
			}
		case 2:
		default:
			return nil
		}
		n := &ffNode{
			id:     id,
			parent: parent,
			entry: BookmarkEntry{
				URL:   url,
				Title: rowText(&r, "title"),
				Kind:  kind,
				Added: firefoxTime(rowIntAny(&r, "dateAdded", "date_added")),
			},
		}
		nodes = append(nodes, n)
		byID[id] = n
		return nil
	}); err != nil {
		return nil, fmt.Errorf("browser: bookmarks: %w", err)
	}

	out := make([]BookmarkEntry, 0, len(nodes))
	for _, n := range nodes {
		n.entry.Path = bookmarkPath(n.id, n.parent, byID)
		out = append(out, n.entry)
	}
	return out, nil
}

// ffNode is one row of moz_bookmarks plus the parent link needed to rebuild
// the folder path Firefox does not store.
type ffNode struct {
	entry  BookmarkEntry
	id     int64
	parent int64
}

// bookmarkPath reconstructs the folder path of a node by walking its parents
// towards the root. The root folder itself (the one whose parent is 0) is
// left out, and a corrupted parent chain stops the walk instead of looping.
func bookmarkPath(id, parent int64, byID map[int64]*ffNode) string {
	var parts []string
	seen := map[int64]bool{id: true}
	cur := parent
	for cur > 0 {
		p, ok := byID[cur]
		if !ok || seen[p.id] {
			break
		}
		seen[p.id] = true
		if p.parent > 0 {
			parts = append(parts, p.entry.Title)
		}
		cur = p.parent
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, " / ")
}
