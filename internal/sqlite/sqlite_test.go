package sqlite

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are committed; see testdata/generate.py for how they were
// built and what the values below mean.

const fixture = "testdata/basic.db"

const unicodeTitle = "Bahasa Indonesia — 日本語 ✅ naïve résumé\nwith a newline, 'quotes' and \"double\""

func mustOpen(t *testing.T, path string) *DB {
	t.Helper()
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func table(t *testing.T, db *DB, name string) *Table {
	t.Helper()
	tbl, err := db.Table(name)
	if err != nil {
		t.Fatalf("Table(%s): %v", name, err)
	}
	return tbl
}

func collect(t *testing.T, tbl *Table) []Row {
	t.Helper()
	var rows []Row
	if err := tbl.Scan(func(r Row) error {
		// Copy the values: Row and its slices are only valid during the
		// callback, exactly like the package documents.
		vals := append([]Value(nil), r.vals...)
		rows = append(rows, Row{t: tbl, rowid: r.rowid, vals: vals})
		return nil
	}); err != nil {
		t.Fatalf("Scan(%s): %v", tbl.Name, err)
	}
	return rows
}

func TestOpenRejectsNonDatabase(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.bin")
	if err := os.WriteFile(junk, []byte("this is not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(junk)
	if err == nil {
		t.Fatal("Open accepted a file that is not a database")
	}
	if !strings.Contains(err.Error(), "not a SQLite database") {
		t.Fatalf("error %q does not say why the file was rejected", err)
	}
	if _, err := Open(filepath.Join(dir, "missing.db")); err == nil {
		t.Fatal("Open succeeded on a missing file")
	}
}

func TestSchema(t *testing.T) {
	db := mustOpen(t, fixture)
	if len(db.Warnings()) != 0 {
		t.Errorf("clean fixture produced warnings: %v", db.Warnings())
	}
	if db.PageSize() != 1024 {
		t.Errorf("page size = %d, want 1024", db.PageSize())
	}
	if db.Encoding() != "UTF-8" {
		t.Errorf("encoding = %q, want UTF-8", db.Encoding())
	}
	if db.PageCount() != 71 {
		t.Errorf("page count = %d, want 71", db.PageCount())
	}

	var names []string
	for _, tbl := range db.Tables() {
		names = append(names, tbl.Name)
	}
	want := []string{"blobs", "odd names", "pk", "sqlite_sequence", "urls", "visits"}
	got := append([]string(nil), names...)
	for i := range got {
		for j := i + 1; j < len(got); j++ {
			if got[j] < got[i] {
				got[i], got[j] = got[j], got[i]
			}
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("tables = %v, want %v (views and indexes must be excluded)", names, want)
	}

	urls := table(t, db, "urls")
	wantCols := []struct {
		name    string
		typ     string
		notNull bool
		pk      bool
	}{
		{"id", "INTEGER", false, true},
		{"url", "LONGVARCHAR", false, false},
		{"title", "LONGVARCHAR", false, false},
		{"visit_count", "INTEGER", true, false},
		{"typed_count", "INTEGER", true, false},
		{"last_visit_time", "INTEGER", true, false},
		{"hidden", "INTEGER", true, false},
	}
	if len(urls.Columns) != len(wantCols) {
		t.Fatalf("urls has %d columns: %+v", len(urls.Columns), urls.Columns)
	}
	for i, w := range wantCols {
		c := urls.Columns[i]
		if c.Name != w.name || c.Type != w.typ || c.NotNull != w.notNull || c.PK != w.pk {
			t.Errorf("urls.%s = %+v, want name=%s type=%s notNull=%v pk=%v", c.Name, c, w.name, w.typ, w.notNull, w.pk)
		}
	}
	if urls.rowidAlias != 0 {
		t.Errorf("urls rowid alias = %d, want 0 (id INTEGER PRIMARY KEY)", urls.rowidAlias)
	}
	if i, ok := urls.Column("URL"); !ok || i != 1 {
		t.Errorf("Column(URL) = %d,%v; names should also match case-insensitively", i, ok)
	}
	if _, ok := urls.Column("nosuch"); ok {
		t.Error("Column(nosuch) reported a match")
	}

	pk := table(t, db, "pk")
	if !pk.WithoutRowid {
		t.Error("pk should be marked WITHOUT ROWID")
	}
}

func TestScanURLs(t *testing.T) {
	db := mustOpen(t, fixture)
	rows := collect(t, table(t, db, "urls"))
	if len(rows) != 400 {
		t.Fatalf("got %d rows, want 400", len(rows))
	}
	for i, r := range rows {
		wantID := int64(i + 1)
		if r.RowID() != wantID {
			t.Fatalf("row %d has rowid %d, want %d", i, r.RowID(), wantID)
		}
		// The INTEGER PRIMARY KEY is an alias of the rowid: the record holds
		// NULL, and readers must still see the key.
		idVal, _ := r.Get("id")
		if id := idVal.Int(); id != wantID {
			t.Errorf("row %d id = %d, want %d (rowid alias)", i, id, wantID)
		}
		if got, _ := r.Get("url"); got.Text() != fmt.Sprintf("https://example.test/%d", wantID) {
			t.Errorf("row %d url = %q", i, got.Text())
		}
		visitCount, _ := r.Get("visit_count")
		if visitCount.Int() != wantID%97 {
			t.Errorf("row %d visit_count = %d, want %d", i, visitCount.Int(), wantID%97)
		}
		lastVisit, _ := r.Get("last_visit_time")
		if lastVisit.Int() != 1000000+wantID*1000 {
			t.Errorf("row %d last_visit_time = %d", i, lastVisit.Int())
		}
		hidden, _ := r.Get("hidden")
		wantHidden := int64(0)
		if wantID%11 == 0 {
			wantHidden = 1
		}
		if hidden.Int() != wantHidden {
			t.Errorf("row %d hidden = %d, want %d", i, hidden.Int(), wantHidden)
		}
		title, _ := r.Get("title")
		switch {
		case wantID == 7:
			if len(title.Text()) != 6405 {
				t.Errorf("overflowing title is %d bytes, want 6405", len(title.Text()))
			}
		case wantID%5 == 0:
			if title.Text() != unicodeTitle {
				t.Errorf("row %d title = %q, want the unicode fixture title", i, title.Text())
			}
		default:
			if title.Text() != fmt.Sprintf("title %d", wantID) {
				t.Errorf("row %d title = %q", i, title.Text())
			}
		}
		if _, ok := r.Get("nosuchcolumn"); ok {
			t.Errorf("row %d: Get(nosuchcolumn) claimed a match", i)
		}
	}
}

func TestScanVisitsAndForeignKeys(t *testing.T) {
	db := mustOpen(t, fixture)
	urls := table(t, db, "urls")
	rows := collect(t, table(t, db, "visits"))
	if len(rows) != 800 {
		t.Fatalf("got %d visits, want 800", len(rows))
	}
	first := rows[0]
	from, _ := first.Get("from_visit")
	if !from.IsNull() {
		t.Errorf("first visit from_visit = %v, want NULL", from)
	}
	second := rows[1]
	from, _ = second.Get("from_visit")
	if from.Int() != 1 {
		t.Errorf("second visit from_visit = %d, want 1", from.Int())
	}
	// Every visits.url must resolve to a urls row through the rowid alias.
	idIndex, ok := urls.Column("id")
	if !ok {
		t.Fatal("urls has no id column")
	}
	seen := map[int64]bool{}
	if err := urls.Scan(func(r Row) error {
		seen[r.At(idIndex).Int()] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i, r := range rows {
		u, _ := r.Get("url")
		if !seen[u.Int()] {
			t.Fatalf("visit %d references urls.id %d, which does not exist", i, u.Int())
		}
		dur, _ := r.Get("visit_duration")
		if dur.Int() != int64(i+1)*500 {
			t.Errorf("visit %d duration = %d, want %d", i, dur.Int(), (i+1)*500)
		}
	}
}

func TestQuotedAndBracketIdentifiers(t *testing.T) {
	db := mustOpen(t, fixture)
	tbl := table(t, db, "odd names")
	if len(tbl.Columns) != 5 {
		t.Fatalf("odd names has %d columns, want 5: %+v", len(tbl.Columns), tbl.Columns)
	}
	want := []string{"quoted col", "bracket col", "backtick col", "c", "d"}
	for i, w := range want {
		if tbl.Columns[i].Name != w {
			t.Errorf("column %d = %q, want %q", i, tbl.Columns[i].Name, w)
		}
	}
	rows := collect(t, tbl)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	c, _ := rows[0].Get("c")
	if c.Int() != 10 {
		t.Errorf("first row c = %d, want 10", c.Int())
	}
	bracket, _ := rows[1].Get("bracket col")
	if !bracket.IsNull() {
		t.Errorf("second row bracket col = %v, want NULL", bracket)
	}
	backtick, _ := rows[1].Get("backtick col")
	if backtick.Text() != "ссылка" {
		t.Errorf("second row backtick col = %q", backtick.Text())
	}
	// A constant DEFAULT is materialised into the record by INSERT, so the
	// column arrives with its value even though the statement never named
	// it. (The format only omits trailing values after ALTER TABLE ADD
	// COLUMN; the reader reports those as NULL rather than inventing a
	// default it cannot evaluate.)
	d, ok := rows[0].Get("d")
	if !ok {
		t.Fatal("column d is missing from the schema")
	}
	if d.Text() != "x" {
		t.Errorf("d = %q, want the DEFAULT value x", d.Text())
	}
}

func TestBlobAndRealValues(t *testing.T) {
	db := mustOpen(t, fixture)
	rows := collect(t, table(t, db, "blobs"))
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want 4", len(rows))
	}
	if b, _ := rows[0].Get("data"); len(b.Blob()) != 0 {
		t.Errorf("first blob has %d bytes, want 0", len(b.Blob()))
	}
	if f, _ := rows[0].Get("f"); !f.IsNull() {
		t.Errorf("first f = %v, want NULL", f)
	}
	second, _ := rows[1].Get("data")
	want := make([]byte, 256)
	for i := range want {
		want[i] = byte(i)
	}
	if !bytes.Equal(second.Blob(), want) {
		t.Errorf("second blob = %d bytes starting %v, want a full 0..255 range", len(second.Blob()), second.Blob()[:8])
	}
	if f, _ := rows[1].Get("f"); f.Float() != -1.5 {
		t.Errorf("second f = %v, want -1.5", f.Float())
	}
	if n, _ := rows[3].Get("n"); n.Text() != unicodeTitle {
		t.Errorf("fourth n = %q, want the unicode fixture title", n.Text())
	}
	if b, _ := rows[3].Get("data"); !b.IsNull() {
		t.Errorf("fourth data = %v, want NULL", b)
	}
}

func TestWithoutRowidTableIsRefused(t *testing.T) {
	db := mustOpen(t, fixture)
	err := table(t, db, "pk").Scan(func(Row) error { return nil })
	if err == nil {
		t.Fatal("Scan succeeded on a WITHOUT ROWID table")
	}
	if !strings.Contains(err.Error(), "WITHOUT ROWID") {
		t.Errorf("error %q does not explain the refusal", err)
	}
}

func TestSQLiteSequenceIsReadable(t *testing.T) {
	db := mustOpen(t, fixture)
	rows := collect(t, table(t, db, "sqlite_sequence"))
	seqs := map[string]int64{}
	for _, r := range rows {
		name, _ := r.Get("name")
		seq, _ := r.Get("seq")
		seqs[name.Text()] = seq.Int()
	}
	if seqs["urls"] != 400 || seqs["visits"] != 800 {
		t.Errorf("sequence counters = %v, want urls=400 and visits=800", seqs)
	}
}

func TestUTF16Database(t *testing.T) {
	db := mustOpen(t, "testdata/utf16.db")
	if db.Encoding() != "UTF-16le" {
		t.Fatalf("encoding = %q, want UTF-16le", db.Encoding())
	}
	rows := collect(t, table(t, db, "t"))
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	if s, _ := rows[0].Get("s"); s.Text() != unicodeTitle {
		t.Errorf("first s = %q, want the unicode fixture title", s.Text())
	}
	if s, _ := rows[1].Get("s"); s.Text() != "plain ascii" {
		t.Errorf("second s = %q", s.Text())
	}
	if s, _ := rows[2].Get("s"); !s.IsNull() {
		t.Errorf("third s = %v, want NULL", s)
	}
}

func TestEmptyDatabase(t *testing.T) {
	db := mustOpen(t, "testdata/empty.db")
	if len(db.Tables()) != 0 {
		t.Errorf("empty.db reports tables: %v", db.Tables())
	}
	if len(db.Warnings()) == 0 {
		t.Error("an empty database should warn that it has no tables")
	}
	if _, err := db.Table("anything"); err == nil {
		t.Error("Table(Anything) succeeded on a database with no tables")
	}
}

// TestWriteAheadLog is the reason this package exists: Chrome and Firefox
// keep their most recent activity in the WAL, and a reader that only opens
// the main file sees none of it.
func TestWriteAheadLog(t *testing.T) {
	db := mustOpen(t, "testdata/wal.db")
	tbl := table(t, db, "t")
	rows := collect(t, tbl)
	if len(rows) != 50 {
		t.Fatalf("WAL-backed scan returned %d rows, want 50", len(rows))
	}
	if s, _ := rows[49].Get("s"); s.Text() != "wal-row-49" {
		t.Errorf("last row = %q, want wal-row-49", s.Text())
	}

	// The same main file without its log must come back without those rows,
	// which proves they really did arrive from the WAL.
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.db")
	raw, err := os.ReadFile("testdata/wal.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plain, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	empty := mustOpen(t, plain)
	if len(empty.Tables()) == 0 {
		return // the schema has not been checkpointed either
	}
	rows = collect(t, table(t, empty, "t"))
	if len(rows) != 0 {
		t.Fatalf("main file alone holds %d rows; the fixture no longer isolates the WAL", len(rows))
	}
}

func TestHotJournalIsReported(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "profile.db")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath+"-journal", []byte("half written transaction"), 0o600); err != nil {
		t.Fatal(err)
	}
	db := mustOpen(t, dbPath)
	found := false
	for _, w := range db.Warnings() {
		if strings.Contains(w, "journal") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings %v do not mention the hot journal", db.Warnings())
	}
}

func TestTruncatedDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "short.db")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw[:1500], 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := Open(path)
	if err == nil {
		defer db.Close()
		// The schema may still be reachable; the tables beyond page 1 are
		// not. Either way something must complain and nothing may panic.
		if tbl, terr := db.Table("urls"); terr == nil {
			terr = tbl.Scan(func(Row) error { return nil })
			if terr == nil && len(db.Warnings()) == 0 {
				t.Fatal("a truncated database produced neither an error nor a warning")
			}
		}
		return
	}
	if !strings.Contains(err.Error(), "sqlite:") {
		t.Errorf("error %q is not attributed to the package", err)
	}
}

func TestValueAccessors(t *testing.T) {
	var null Value
	if !null.IsNull() || null.Kind() != KindNull || null.String() != "NULL" {
		t.Errorf("zero Value = %v (kind %d)", null, null.Kind())
	}
	i := Value{kind: KindInt, i: -42}
	if i.Int() != -42 || i.Float() != -42 || i.String() != "-42" {
		t.Errorf("int Value behaves unexpectedly: %s", i)
	}
	f := Value{kind: KindFloat, f: 2.5}
	if f.Float() != 2.5 || f.Int() != 2 {
		t.Errorf("float Value = %v/%d, want 2.5/2", f.Float(), f.Int())
	}
	txt := Value{kind: KindText, s: "abc"}
	if txt.Text() != "abc" || txt.Int() != 0 {
		t.Errorf("text Value = %q/%d", txt.Text(), txt.Int())
	}
	b := Value{kind: KindBlob, b: []byte{1, 2}}
	if b.String() != "<blob 2 bytes>" {
		t.Errorf("blob String() = %q", b.String())
	}
}
