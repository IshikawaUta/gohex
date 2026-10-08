package sqlite

import (
	"encoding/binary"
	"fmt"
	"math"
)

// getVarint decodes one SQLite variable-length integer: up to nine bytes,
// seven bits per byte for the first eight and all eight bits of the ninth,
// most significant group first. The second result is how many bytes were
// consumed.
func getVarint(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < 9; i++ {
		if i >= len(b) {
			return 0, 0, fmt.Errorf("truncated varint")
		}
		c := b[i]
		if i == 8 {
			return v<<8 | uint64(c), 9, nil
		}
		v = v<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return v, 9, nil
}

// beInt decodes a big-endian two's-complement integer of 1..8 bytes and
// sign-extends it.
func beInt(b []byte) int64 {
	var u uint64
	for _, c := range b {
		u = u<<8 | uint64(c)
	}
	if bits := uint(len(b) * 8); bits < 64 && u&(1<<(bits-1)) != 0 {
		u |= ^uint64(0) << bits
	}
	return int64(u)
}

// localPayload returns how many bytes of a table-leaf cell payload stay on
// the b-tree page; the rest spills to overflow pages. The arithmetic is
// fixed by the file format and must not be simplified — changing it would
// read the wrong byte range from every overflowing row.
func localPayload(p, usable int64) int64 {
	x := usable - 35
	if p <= x {
		return p
	}
	m := ((usable-12)*32)/255 - 23
	k := m + ((p - m) % (usable - 4))
	if k <= x {
		return k
	}
	return m
}

// decodeRecord turns a cell payload into column values. The header records
// one serial type per column; the body follows. A record may hold fewer
// values than its table has columns (after ALTER TABLE ADD COLUMN), in which
// case the missing trailing values come back as NULL — applying column
// defaults would need expression evaluation the reader does not attempt.
func (db *DB) decodeRecord(payload []byte) ([]Value, error) {
	hdrSize, n, err := getVarint(payload)
	if err != nil {
		return nil, fmt.Errorf("record header: %w", err)
	}
	if hdrSize < uint64(n) || hdrSize > uint64(len(payload)) {
		return nil, fmt.Errorf("record header claims %d bytes of a %d byte payload", hdrSize, len(payload))
	}
	types := make([]uint64, 0, 8)
	off := n
	for off < int(hdrSize) {
		st, m, err := getVarint(payload[off:int(hdrSize)])
		if err != nil {
			return nil, fmt.Errorf("record header: %w", err)
		}
		types = append(types, st)
		off += m
	}
	body := payload[int(hdrSize):]
	vals := make([]Value, len(types))
	pos := 0
	for i, st := range types {
		v, used, err := db.decodeValue(st, body[pos:])
		if err != nil {
			return nil, fmt.Errorf("column %d (serial type %d): %w", i, st, err)
		}
		vals[i] = v
		pos += used
	}
	return vals, nil
}

// decodeValue decodes one value of the given serial type and reports how
// many bytes it consumed.
//
// Serial types 10 and 11 are reserved and, per the format, "will never
// appear in a well-formed database file". They are read as NULL rather than
// rejected: one bad byte must not cost the caller the rest of the table.
func (db *DB) decodeValue(st uint64, b []byte) (Value, int, error) {
	need := func(n int) error {
		if len(b) < n {
			return fmt.Errorf("value runs past the end of the record (%d bytes left)", len(b))
		}
		return nil
	}
	switch st {
	case 0:
		return Value{kind: KindNull}, 0, nil
	case 1, 2, 3, 4, 5, 6:
		n := []int{0, 1, 2, 3, 4, 6, 8}[st]
		if err := need(n); err != nil {
			return Value{}, 0, err
		}
		return Value{kind: KindInt, i: beInt(b[:n])}, n, nil
	case 7:
		if err := need(8); err != nil {
			return Value{}, 0, err
		}
		return Value{kind: KindFloat, f: math.Float64frombits(binary.BigEndian.Uint64(b[:8]))}, 8, nil
	case 8:
		return Value{kind: KindInt, i: 0}, 0, nil
	case 9:
		return Value{kind: KindInt, i: 1}, 0, nil
	case 10, 11:
		return Value{kind: KindNull}, 0, nil
	}
	if st >= 12 {
		var n int
		if st%2 == 0 { // even: BLOB of (N-12)/2 bytes
			n = int((st - 12) / 2)
			if err := need(n); err != nil {
				return Value{}, 0, err
			}
			return Value{kind: KindBlob, b: b[:n]}, n, nil
		}
		n = int((st - 13) / 2) // odd: TEXT of (N-13)/2 bytes
		if err := need(n); err != nil {
			return Value{}, 0, err
		}
		return Value{kind: KindText, s: db.decodeText(b[:n])}, n, nil
	}
	return Value{}, 0, fmt.Errorf("unknown serial type %d", st)
}
