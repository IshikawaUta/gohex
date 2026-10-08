package sqlite

import (
	"encoding/binary"
	"fmt"
)

// B-tree page types from the file format.
const (
	pageInteriorIndex = 0x02
	pageInteriorTable = 0x05
	pageLeafIndex     = 0x0a
	pageLeafTable     = 0x0d
)

// rowFn receives one decoded row. Returning an error stops the scan and
// propagates to the caller.
type rowFn func(rowid int64, vals []Value) error

// scanTree streams every row of the table b-tree rooted at page n in key
// (rowid) order.
func (db *DB) scanTree(n int64, fn rowFn) error {
	return db.walkPage(n, 0, fn)
}

// walkPage descends one level of a table b-tree. depth guards against a
// cycle in a damaged file, where a child pointer can point back at an
// ancestor.
func (db *DB) walkPage(n int64, depth int, fn rowFn) error {
	if depth > maxTreeDepth {
		return fmt.Errorf("sqlite: %s: b-tree deeper than %d pages at page %d (cyclic or corrupt)", db.path, maxTreeDepth, n)
	}
	page, err := db.page(n)
	if err != nil {
		return err
	}
	// On page 1 the first 100 bytes are the database header; the b-tree
	// header follows it. Cell pointers, unlike this base offset, are counted
	// from byte 0 of the page and therefore already include those 100 bytes.
	base := int64(0)
	if n == 1 {
		base = 100
	}
	if int64(len(page)) < base+8 {
		return fmt.Errorf("sqlite: %s: page %d is too short to hold a b-tree header", db.path, n)
	}
	hdr := page[base:]
	kind := hdr[0]
	cellCount := int(binary.BigEndian.Uint16(hdr[3:5]))
	if cellCount > maxCellsPerPage {
		return fmt.Errorf("sqlite: %s: page %d claims %d cells", db.path, n, cellCount)
	}
	headerSize := 8
	switch kind {
	case pageInteriorTable:
		headerSize = 12
	case pageLeafTable:
		// header stays 8
	default:
		if kind == pageInteriorIndex || kind == pageLeafIndex {
			return fmt.Errorf("sqlite: %s: page %d is an index b-tree page (0x%02x); this table is WITHOUT ROWID and cannot be scanned", db.path, n, kind)
		}
		return fmt.Errorf("sqlite: %s: page %d has unknown b-tree page type 0x%02x", db.path, n, kind)
	}
	if int64(len(page)) < base+int64(headerSize)+int64(cellCount)*2 {
		return fmt.Errorf("sqlite: %s: page %d cell pointer array overruns the page", db.path, n)
	}
	pointers := hdr[headerSize : headerSize+cellCount*2]

	switch kind {
	case pageInteriorTable:
		for i := 0; i < cellCount; i++ {
			off := int64(binary.BigEndian.Uint16(pointers[i*2:]))
			child, err := db.childAt(page, n, off)
			if err != nil {
				return err
			}
			if err := db.walkPage(child, depth+1, fn); err != nil {
				return err
			}
		}
		// The right-most pointer is not a cell: it is a bare 4-byte page
		// number held in the b-tree header, so it must not be read through
		// childAt, which treats its argument as a byte offset.
		right := int64(binary.BigEndian.Uint32(hdr[8:12]))
		return db.walkPage(right, depth+1, fn)
	default: // pageLeafTable
		usable := int64(db.usable)
		for i := 0; i < cellCount; i++ {
			off := int64(binary.BigEndian.Uint16(pointers[i*2:]))
			if off < base || off >= usable {
				return fmt.Errorf("sqlite: %s: page %d cell %d points to offset %d outside [0,%d)", db.path, n, i, off, usable)
			}
			rowid, payload, err := db.readLeafCell(page, off, usable)
			if err != nil {
				return fmt.Errorf("sqlite: %s: page %d cell %d: %w", db.path, n, i, err)
			}
			vals, err := db.decodeRecord(payload)
			if err != nil {
				return fmt.Errorf("sqlite: %s: row %d: %w", db.path, rowid, err)
			}
			if err := fn(rowid, vals); err != nil {
				return err
			}
		}
		return nil
	}
}

// childAt reads the 4-byte page number at off, which on an interior page
// points at the child for all keys up to the key stored in the same cell
// (or, for the right-most pointer, everything above it).
func (db *DB) childAt(page []byte, n, off int64) (int64, error) {
	if off < 0 || off+4 > int64(db.usable) {
		return 0, fmt.Errorf("sqlite: %s: page %d child pointer at offset %d is out of range", db.path, n, off)
	}
	return int64(binary.BigEndian.Uint32(page[off : off+4])), nil
}

// readLeafCell decodes one table-leaf cell: payload size varint, rowid
// varint, the bytes of payload that fit on the page, and — when the payload
// is larger — the page number of the overflow chain.
func (db *DB) readLeafCell(page []byte, off, usable int64) (int64, []byte, error) {
	size, n, err := getVarint(page[off:usable])
	if err != nil {
		return 0, nil, fmt.Errorf("payload size: %w", err)
	}
	if size > maxPayload {
		return 0, nil, fmt.Errorf("payload of %d bytes exceeds the %d byte limit", size, maxPayload)
	}
	rowidRaw, n2, err := getVarint(page[off+int64(n) : usable])
	if err != nil {
		return 0, nil, fmt.Errorf("rowid: %w", err)
	}
	start := off + int64(n) + int64(n2)
	local := localPayload(int64(size), usable)
	if start+local > usable {
		return 0, nil, fmt.Errorf("cell claims %d payload bytes but the page ends at %d", local, usable)
	}
	payload := make([]byte, 0, local)
	payload = append(payload, page[start:start+local]...)
	if int64(size) <= local {
		return int64(rowidRaw), payload, nil
	}
	if start+local+4 > usable {
		return 0, nil, fmt.Errorf("overflow pointer overruns the page")
	}
	next := int64(binary.BigEndian.Uint32(page[start+local : start+local+4]))
	rest, err := db.readOverflow(next, int(size)-len(payload))
	if err != nil {
		return 0, nil, err
	}
	payload = append(payload, rest...)
	return int64(rowidRaw), payload, nil
}

// readOverflow follows an overflow chain, appending up to need more bytes.
// Each overflow page holds a 4-byte link to the next page and then usable-4
// bytes of content.
func (db *DB) readOverflow(next int64, need int) ([]byte, error) {
	if need == 0 {
		return nil, nil
	}
	usable := int64(db.usable)
	out := make([]byte, 0, need)
	for next != 0 && len(out) < need {
		p, err := db.page(next)
		if err != nil {
			return nil, fmt.Errorf("overflow page %d: %w", next, err)
		}
		if int64(len(p)) < usable {
			return nil, fmt.Errorf("overflow page %d is shorter than the usable page size", next)
		}
		nxt := int64(binary.BigEndian.Uint32(p[0:4]))
		body := p[4:usable]
		take := need - len(out)
		if take > len(body) {
			take = len(body)
		}
		out = append(out, body[:take]...)
		next = nxt
	}
	if len(out) < need {
		return nil, fmt.Errorf("overflow chain ended after %d of %d bytes", len(out), need)
	}
	return out, nil
}
