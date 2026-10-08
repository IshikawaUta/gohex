// Package sqlite implements a read-only reader for SQLite database files.
//
// It exists because GoHex must read browser artifacts (Chrome History,
// Firefox places.sqlite, Safari History.db) without linking a SQLite
// implementation: the cross-compile build runs with CGO_ENABLED=0, and a
// half-trusted cgo binding would drag a second SQL engine into a code base
// that already parses FAT, NTFS, ext and ISO 9660 by hand.
//
// Scope, deliberately: open a database, list its tables, and stream their
// rows. There is no SQL parser, no query planner, no index traversal and no
// writes. Callers filter in Go after a full table scan, which is also what a
// forensic examination wants — a scan reads every row exactly once and does
// not depend on indexes that may be stale or absent from a copy.
//
// Two companions are honoured:
//
//   - the write-ahead log (<db>-wal), so rows that have not been checkpointed
//     yet are still visible. Chrome and Firefox both run in WAL mode, so
//     ignoring it would silently hide the most recent browsing activity;
//   - a rollback journal (<db>-journal) is only detected and reported as a
//     warning. Simulating a rollback is out of scope, and the main file may
//     hold uncommitted pages, so callers must treat the data as provisional.
//
// Corrupt input is expected: browser profiles copied from failing disks are
// the normal case. Every offset is bounds-checked and traversal is depth- and
// size-limited, so a damaged file yields an error rather than an allocation
// spiral. A row the reader cannot decode fails that table's scan with a
// message naming the row; it does not abort the whole database.
package sqlite

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf16"
)

const (
	magicString = "SQLite format 3\x00"

	minPageSize = 512
	maxPageSize = 65536

	// Guard rails for hostile or damaged files. A well-formed database never
	// approaches these; they exist so that a corrupt byte cannot make the
	// reader allocate without bound.
	maxTreeDepth    = 64
	maxOverflowPage = 1 << 22 // 4 Mi pages: far beyond any legal chain
	maxPayload      = 64 << 20
	maxCellsPerPage = 1 << 16
	maxSchemaRows   = 1 << 20
)

// Kind classifies a decoded value.
type Kind uint8

// The five storage classes of the record format.
const (
	KindNull Kind = iota
	KindInt
	KindFloat
	KindText
	KindBlob
)

// Value is one decoded column value. The zero Value is NULL.
type Value struct {
	kind Kind
	i    int64
	f    float64
	s    string
	b    []byte
}

// Kind reports the storage class of v.
func (v Value) Kind() Kind { return v.kind }

// IsNull reports whether v is SQL NULL.
func (v Value) IsNull() bool { return v.kind == KindNull }

// Int returns the value as an integer. Non-numeric kinds yield 0.
func (v Value) Int() int64 {
	switch v.kind {
	case KindInt:
		return v.i
	case KindFloat:
		return int64(v.f)
	default:
		return 0
	}
}

// Float returns the value as a float. Integers are converted, other kinds
// yield 0.
func (v Value) Float() float64 {
	switch v.kind {
	case KindFloat:
		return v.f
	case KindInt:
		return float64(v.i)
	default:
		return 0
	}
}

// Text returns the value as a string. It returns "" for anything that was
// not stored as text — use Kind to distinguish an empty string from a number.
func (v Value) Text() string { return v.s }

// Blob returns the raw bytes of a BLOB value. The slice is owned by the row
// that produced it and must not be retained after Scan returns.
func (v Value) Blob() []byte { return v.b }

// String renders v for display. BLOBs are summarised rather than dumped.
func (v Value) String() string {
	switch v.kind {
	case KindNull:
		return "NULL"
	case KindInt:
		return fmt.Sprintf("%d", v.i)
	case KindFloat:
		return fmt.Sprintf("%v", v.f)
	case KindText:
		return v.s
	case KindBlob:
		return fmt.Sprintf("<blob %d bytes>", len(v.b))
	default:
		return "?"
	}
}

// Column is one column of a CREATE TABLE statement as stored in sqlite_master.
type Column struct {
	Name    string
	Type    string // declared type, "" when the statement omits it
	NotNull bool
	PK      bool

	// selfPK is set only when PRIMARY KEY appears in this column's own
	// definition, not in a table-level constraint. SQLite aliases the rowid
	// only for the former, and mistaking one for the other would hand back a
	// key that does not exist.
	selfPK bool
}

// DB is an open, read-only database.
type DB struct {
	path      string
	f         *os.File
	pageSize  uint32
	usable    uint32 // pageSize - reserved bytes
	textEnc   int    // 1 UTF-8, 2 UTF-16le, 3 UTF-16be
	filePages int64
	pages     int64
	wal       *walOverlay
	warnings  []string
	tables    []*Table
	byName    map[string]*Table
}

// Open opens path read-only and parses its schema.
//
// The file is never modified: SQLite is not invoked, no journal is replayed
// and no -shm file is created. A file that is not a SQLite database is
// rejected by its 16-byte magic string, never by its extension.
func Open(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	db := &DB{path: path, f: f, textEnc: 1, byName: map[string]*Table{}}
	if err := db.init(); err != nil {
		f.Close()
		return nil, err
	}
	return db, nil
}

// Close releases the underlying file. Further reads fail.
func (db *DB) Close() error {
	db.wal.close()
	if db.f == nil {
		return nil
	}
	err := db.f.Close()
	db.f = nil
	return err
}

// Path returns the file this database was opened from.
func (db *DB) Path() string { return db.path }

// PageSize returns the database page size in bytes.
func (db *DB) PageSize() uint32 { return db.pageSize }

// Encoding returns the text encoding of the file: "UTF-8", "UTF-16le" or
// "UTF-16be".
func (db *DB) Encoding() string {
	switch db.textEnc {
	case 2:
		return "UTF-16le"
	case 3:
		return "UTF-16be"
	default:
		return "UTF-8"
	}
}

// PageCount returns how many pages the database is believed to have, taking
// the write-ahead log into account.
func (db *DB) PageCount() int64 { return db.pages }

// Warnings returns non-fatal observations made while opening the database:
// a hot journal, a write-ahead log that could not be applied, a file whose
// size disagrees with its header. An empty slice means the file looked
// exactly as a clean, fully checkpointed database should.
func (db *DB) Warnings() []string { return db.warnings }

// Tables returns the tables in schema order. Views, indexes and triggers are
// not tables and are not included.
func (db *DB) Tables() []*Table { return db.tables }

// Table returns the named table, or an error listing what the database does
// contain.
func (db *DB) Table(name string) (*Table, error) {
	if t, ok := db.byName[name]; ok {
		return t, nil
	}
	names := make([]string, 0, len(db.tables))
	for _, t := range db.tables {
		names = append(names, t.Name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("sqlite: %s has no tables", db.path)
	}
	return nil, fmt.Errorf("sqlite: %s has no table %q (tables: %s)", db.path, name, strings.Join(names, ", "))
}

func (db *DB) warnf(format string, args ...any) {
	db.warnings = append(db.warnings, fmt.Sprintf(format, args...))
}

func (db *DB) init() error {
	var hdr [100]byte
	n, err := io.ReadFull(db.f, hdr[:])
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("sqlite: %s: %w", db.path, err)
	}
	// The magic string is checked before the size so a file that is merely
	// short still reports what it actually is: not a database.
	if n < len(magicString) {
		return fmt.Errorf("sqlite: %s: too short to be a SQLite database (%d bytes)", db.path, n)
	}
	if string(hdr[:16]) != magicString {
		return fmt.Errorf("sqlite: %s: not a SQLite database (bad magic)", db.path)
	}
	if n < len(hdr) {
		return fmt.Errorf("sqlite: %s: database header is truncated (%d of %d bytes)", db.path, n, len(hdr))
	}

	pageSize := uint32(binary.BigEndian.Uint16(hdr[16:18]))
	if pageSize == 1 {
		pageSize = maxPageSize // the 65536 encoding
	}
	if pageSize < minPageSize || pageSize > maxPageSize || pageSize&(pageSize-1) != 0 {
		return fmt.Errorf("sqlite: %s: invalid page size %d", db.path, pageSize)
	}
	reserved := uint32(hdr[20])
	usable := pageSize - reserved
	if usable < 480 {
		return fmt.Errorf("sqlite: %s: reserved bytes %d leave a usable page of %d (<480)", db.path, reserved, usable)
	}
	enc := binary.BigEndian.Uint32(hdr[56:60])
	if enc == 0 {
		// A database that has only ever written meta (or that runs in WAL
		// mode with nothing checkpointed) leaves the field at zero, and
		// SQLite itself reports that as UTF-8.
		enc = 1
	}
	if enc != 1 && enc != 2 && enc != 3 {
		return fmt.Errorf("sqlite: %s: invalid text encoding %d", db.path, enc)
	}
	db.pageSize, db.usable, db.textEnc = pageSize, usable, int(enc)

	info, err := db.f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	db.filePages = size / int64(pageSize)
	if size%int64(pageSize) != 0 {
		db.warnf("file size %d is not a multiple of the page size %d; the tail is ignored", size, pageSize)
	}
	if db.filePages == 0 {
		return fmt.Errorf("sqlite: %s: file is smaller than one page", db.path)
	}
	db.pages = db.filePages

	// The in-header page count is only trustworthy when the change counter
	// matches the version-valid-for number (SQLite file format 1.3.7).
	if hdrPages := headerPageCount(hdr[:]); hdrPages > db.pages {
		db.pages = hdrPages
	}
	if hdr[19] > 2 {
		db.warnf("unknown file format read version %d; attempting to read anyway", hdr[19])
	}
	if j, err := os.Stat(db.path + "-journal"); err == nil && j.Size() > 0 {
		db.warnf("hot rollback journal %s-journal (%d bytes) is present; the database may be mid-transaction and its pages uncommitted",
			db.path, j.Size())
	}
	if err := db.applyWAL(); err != nil {
		return err
	}
	return db.loadSchema()
}

// page returns the raw contents of page n, preferring the write-ahead log.
func (db *DB) page(n int64) ([]byte, error) {
	if n < 1 {
		return nil, fmt.Errorf("sqlite: %s: invalid page number %d", db.path, n)
	}
	if n > 0xFFFFFFFE {
		return nil, fmt.Errorf("sqlite: %s: invalid page number %d", db.path, n)
	}
	if db.wal != nil {
		if p := db.wal.page(n); p != nil {
			return p, nil
		}
	}
	if n > db.pages {
		return nil, fmt.Errorf("sqlite: %s: page %d is beyond the end of the database (%d pages)", db.path, n, db.pages)
	}
	buf := make([]byte, db.pageSize)
	if _, err := db.f.ReadAt(buf, (n-1)*int64(db.pageSize)); err != nil {
		return nil, fmt.Errorf("sqlite: %s: read page %d: %w", db.path, n, err)
	}
	return buf, nil
}

// decodeText converts bytes in the database's text encoding to a Go string.
func (db *DB) decodeText(b []byte) string {
	switch db.textEnc {
	case 2:
		return string(utf16Decode(b, false))
	case 3:
		return string(utf16Decode(b, true))
	default:
		return string(b)
	}
}

// utf16Decode decodes UTF-16 code units, swapping byte order first when the
// stored text is big-endian. An odd trailing byte is dropped rather than
// reported: a damaged title should not abort a table scan.
func utf16Decode(b []byte, bigEndian bool) []rune {
	if len(b) < 2 {
		return nil
	}
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if bigEndian {
			units = append(units, binary.BigEndian.Uint16(b[i:i+2]))
		} else {
			units = append(units, binary.LittleEndian.Uint16(b[i:i+2]))
		}
	}
	return utf16.Decode(units)
}
