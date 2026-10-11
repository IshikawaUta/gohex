package browser

import (
	"errors"
	"fmt"
	"sort"

	"github.com/IshikawaUta/gohex/internal/sqlite"
)

// errTableMissing marks a table a browser is expected to have but this file
// does not. It is downgraded to a warning by Report.absorb so one drifted
// schema cannot throw away the artefacts that were read successfully.
var errTableMissing = errors.New("browser: required table is missing")

// Read extracts the browsing artefacts of a single profile.
//
// Read is strictly read-only: the databases are opened without write access
// and a write-ahead log is interpreted rather than checkpointed, so the
// evidence file is left byte-for-byte as it was found. A profile whose
// database is missing or corrupt returns an error; a profile that merely
// lacks one kind of artefact returns a report with that slice empty and the
// reason recorded in Warnings.
func Read(p Profile) (Report, error) {
	switch p.Browser {
	case Chrome:
		return readChromium(p)
	case Firefox:
		return readFirefox(p)
	case Safari:
		return readSafari(p)
	}
	return Report{}, fmt.Errorf("browser: unsupported browser %q", p.Browser)
}

// openRead opens a database for reading, reporting a missing file as
// ErrNotFound so callers can tell "no artefact" from "corrupt artefact".
func openRead(path string) (*sqlite.DB, error) {
	if !isFile(path) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	db, err := sqlite.Open(path)
	if err != nil {
		return nil, fmt.Errorf("browser: %w", err)
	}
	return db, nil
}

// tableFor returns a table by name, or errTableMissing. Callers treat that
// error as a warning: browser schemas drift between versions, and a renamed
// column must degrade the result rather than fail the whole profile.
func tableFor(db *sqlite.DB, name string) (*sqlite.Table, error) {
	t, err := db.Table(name)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %w", errTableMissing, name, err)
	}
	return t, nil
}

// absorb records err in Warnings when it only means "this table is absent"
// and returns it unchanged otherwise, so the caller can propagate real
// failures.
func (r *Report) absorb(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errTableMissing) {
		r.Warnings = append(r.Warnings, err.Error())
		return nil
	}
	return err
}

// takeWarnings copies the SQLite reader's own warnings — an unverifiable
// write-ahead log, an unparsable schema — into the report.
func (r *Report) takeWarnings(db *sqlite.DB) {
	r.Warnings = append(r.Warnings, db.Warnings()...)
}

// rowText reads a text column, returning "" when the column does not exist
// in this version of the schema.
func rowText(r *sqlite.Row, name string) string {
	if v, ok := r.Get(name); ok {
		return v.Text()
	}
	return ""
}

// rowInt reads an integer column, returning 0 when it is absent.
func rowInt(r *sqlite.Row, name string) int64 {
	if v, ok := r.Get(name); ok {
		return v.Int()
	}
	return 0
}

// rowFloat reads a floating-point column, returning 0 when it is absent.
func rowFloat(r *sqlite.Row, name string) float64 {
	if v, ok := r.Get(name); ok {
		return v.Float()
	}
	return 0
}

// rowIntAny reads the first of the named columns the schema carries. Firefox
// mixes camelCase (dateAdded) with snake_case (last_visit_date), and older
// builds differ again, so the reader asks for the alternatives in turn rather
// than betting the whole artefact on one spelling.
func rowIntAny(r *sqlite.Row, names ...string) int64 {
	for _, n := range names {
		if v, ok := r.Get(n); ok {
			return v.Int()
		}
	}
	return 0
}

// rowPresent reports whether the schema carries the named column at all.
func rowPresent(r *sqlite.Row, name string) bool {
	_, ok := r.Get(name)
	return ok
}

// sortHistory orders entries newest first, falling back to the URL so the
// output of two runs over the same file is identical.
func sortHistory(h []HistoryEntry) {
	sort.SliceStable(h, func(i, j int) bool {
		if !h[i].LastVisit.Equal(h[j].LastVisit) {
			return h[i].LastVisit.After(h[j].LastVisit)
		}
		return h[i].URL < h[j].URL
	})
}

// sortDownloads orders entries by start time, newest first.
func sortDownloads(d []DownloadEntry) {
	sort.SliceStable(d, func(i, j int) bool {
		if !d[i].Start.Equal(d[j].Start) {
			return d[i].Start.After(d[j].Start)
		}
		return d[i].URL < d[j].URL
	})
}

// sortBookmarks orders entries by folder path then title, which is the order
// a tree view walks them in.
func sortBookmarks(b []BookmarkEntry) {
	sort.SliceStable(b, func(i, j int) bool {
		if b[i].Path != b[j].Path {
			return b[i].Path < b[j].Path
		}
		return b[i].Title < b[j].Title
	})
}
