package browser

import (
	"fmt"
	"path/filepath"

	"github.com/IshikawaUta/gohex/internal/sqlite"
)

// readSafari reads Safari's History.db. Safari keeps no downloads in it, and
// its bookmarks are a binary property list rather than a database, so this
// profile yields history only.
func readSafari(p Profile) (Report, error) {
	r := Report{Profile: p}
	db, err := openRead(filepath.Join(p.Dir, "History.db"))
	if err != nil {
		return r, err
	}
	defer db.Close()

	if r.History, err = safariHistory(db); err != nil {
		if err := r.absorb(err); err != nil {
			return r, err
		}
	}
	r.takeWarnings(db)
	sortHistory(r.History)
	return r, nil
}

// safariVisit summarises the visit rows that point at one history item.
type safariVisit struct {
	// at is the most recent Core Data timestamp seen for the item.
	at float64
	// title is the title recorded by that most recent visit which carried
	// one; Safari rewrites the title on every visit, so an earlier non-empty
	// title is better than nothing.
	title   string
	titleAt float64
}

// safariHistory joins history_items and history_visits in Go rather than in
// SQL. A join would have to name columns this reader may not have found, and
// a failed query would cost the caller the whole artefact.
func safariHistory(db *sqlite.DB) ([]HistoryEntry, error) {
	itemTable, err := tableFor(db, "history_items")
	if err != nil {
		return nil, err
	}
	visitTable, err := tableFor(db, "history_visits")
	if err != nil {
		return nil, err
	}

	type item struct {
		url    string
		title  string
		visits int64
		visit  safariVisit
		have   bool
	}
	byID := map[int64]*item{}
	var order []int64

	if err := itemTable.Scan(func(r sqlite.Row) error {
		id := rowInt(&r, "id")
		if id <= 0 {
			return nil
		}
		byID[id] = &item{
			url:    rowText(&r, "url"),
			title:  rowText(&r, "title"),
			visits: rowInt(&r, "visit_count"),
		}
		order = append(order, id)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("browser: history: %w", err)
	}

	if err := visitTable.Scan(func(r sqlite.Row) error {
		it, ok := byID[rowInt(&r, "history_item")]
		if !ok {
			return nil // an orphan visit has no URL to attach itself to
		}
		at := rowFloat(&r, "visit_time")
		title := rowText(&r, "title")
		if at > it.visit.at {
			it.visit.at = at
			it.have = true
		}
		if title != "" && (it.visit.title == "" || at >= it.visit.titleAt) {
			it.visit.title, it.visit.titleAt = title, at
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("browser: history: %w", err)
	}

	out := make([]HistoryEntry, 0, len(order))
	for _, id := range order {
		it := byID[id]
		if it.url == "" {
			continue
		}
		e := HistoryEntry{
			URL:    it.url,
			Title:  it.title,
			Visits: it.visits,
		}
		if it.visit.title != "" {
			e.Title = it.visit.title
		}
		if it.have {
			e.LastVisit = safariTime(it.visit.at)
		}
		out = append(out, e)
	}
	return out, nil
}
