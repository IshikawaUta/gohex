package sqlite

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Table is a rowid table listed in sqlite_master.
type Table struct {
	db           *DB
	Name         string
	RootPage     int64
	Columns      []Column
	SQL          string
	WithoutRowid bool
	rowidAlias   int // index of the INTEGER PRIMARY KEY that stores nothing, -1 if none
	schemaErr    error
}

// Row is one decoded table row. It is only valid for the duration of the
// Scan callback that produced it.
type Row struct {
	t     *Table
	rowid int64
	vals  []Value
}

// RowID returns the table b-tree key of the row. For a table whose
// INTEGER PRIMARY KEY aliases the rowid this is also that column's value;
// the record itself stores NULL there, which is why the key is exposed
// separately.
func (r *Row) RowID() int64 { return r.rowid }

// Len returns how many values the row actually carries. It can be less than
// the number of columns in the table after ALTER TABLE ADD COLUMN.
func (r *Row) Len() int { return len(r.vals) }

// At returns column i, or NULL when the row is shorter than the schema
// says. The INTEGER PRIMARY KEY is the exception: its value lives in the
// b-tree key, the record stores NULL there, and callers expect the key back
// exactly as SQLite's own SELECT would return it.
func (r *Row) At(i int) Value {
	if i == r.t.rowidAlias {
		return Value{kind: KindInt, i: r.rowid}
	}
	if i < 0 || i >= len(r.vals) {
		return Value{kind: KindNull}
	}
	return r.vals[i]
}

// Get looks a column up by name. The second result is false when the table
// has no such column; a row that simply omits the value reports true with a
// NULL, so callers can tell "not in this schema" from "not in this row".
func (r *Row) Get(name string) (Value, bool) {
	i, ok := r.t.Column(name)
	if !ok {
		return Value{kind: KindNull}, false
	}
	return r.At(i), true
}

// Column returns the index of a column. Names are matched exactly first,
// then case-insensitively, because SQLite folds ASCII case in identifiers.
func (t *Table) Column(name string) (int, bool) {
	for i, c := range t.Columns {
		if c.Name == name {
			return i, true
		}
	}
	for i, c := range t.Columns {
		if strings.EqualFold(c.Name, name) {
			return i, true
		}
	}
	return 0, false
}

// Scan streams every row of the table in rowid order. Stopping early is
// done by returning an error from fn, which Scan then returns unchanged.
//
// Scan fails with a clear message when the table is WITHOUT ROWID (an index
// b-tree the reader does not traverse) or when its CREATE TABLE text could
// not be parsed, rather than delivering rows whose columns nobody can name.
func (t *Table) Scan(fn func(Row) error) error {
	if t.schemaErr != nil {
		return fmt.Errorf("sqlite: table %s: %w", t.Name, t.schemaErr)
	}
	if t.WithoutRowid {
		return fmt.Errorf("sqlite: table %s is WITHOUT ROWID; index b-trees are not supported", t.Name)
	}
	return t.db.scanTree(t.RootPage, func(rowid int64, vals []Value) error {
		return fn(Row{t: t, rowid: rowid, vals: vals})
	})
}

// loadSchema reads sqlite_schema (root page 1) and builds the table list.
func (db *DB) loadSchema() error {
	n := 0
	err := db.scanTree(1, func(_ int64, vals []Value) error {
		n++
		if n > maxSchemaRows {
			return fmt.Errorf("sqlite: %s: schema holds more than %d objects", db.path, maxSchemaRows)
		}
		if len(vals) < 4 {
			return fmt.Errorf("sqlite: %s: schema row has %d values, want at least 4", db.path, len(vals))
		}
		if vals[0].Text() != "table" {
			return nil // views, indexes and triggers are not scannable rows
		}
		name := vals[1].Text()
		if name == "" {
			return nil
		}
		t := &Table{db: db, Name: name, RootPage: vals[3].Int(), rowidAlias: -1}
		if len(vals) > 4 {
			t.SQL = vals[4].Text()
		}
		if t.RootPage <= 0 {
			t.schemaErr = fmt.Errorf("schema reports root page %d", t.RootPage)
			db.warnf("table %s has no root page", name)
		} else if t.SQL != "" {
			_, cols, without, err := parseCreateTable(t.SQL)
			if err != nil {
				t.schemaErr = err
				db.warnf("cannot parse the schema of table %s: %v", name, err)
			} else {
				t.Columns, t.WithoutRowid = cols, without
				t.rowidAlias = -1
				for i, c := range cols {
					if c.selfPK && strings.EqualFold(c.Type, "INTEGER") {
						t.rowidAlias = i
						break
					}
				}
			}
		} else {
			t.schemaErr = fmt.Errorf("schema row has no CREATE TABLE text")
			db.warnf("table %s has no CREATE TABLE text", name)
		}
		db.tables = append(db.tables, t)
		db.byName[name] = t
		return nil
	})
	if err != nil {
		return fmt.Errorf("sqlite: %s: read schema: %w", db.path, err)
	}
	if len(db.tables) == 0 {
		db.warnf("database contains no tables")
	}
	return nil
}

// headerPageCount reads the in-header page count. It only counts when the
// file change counter matches the version-valid-for number; otherwise the
// real file size is the truth and 0 is returned to say so.
func headerPageCount(hdr []byte) int64 {
	if binary.BigEndian.Uint32(hdr[24:28]) != binary.BigEndian.Uint32(hdr[92:96]) {
		return 0
	}
	return int64(binary.BigEndian.Uint32(hdr[28:32]))
}
