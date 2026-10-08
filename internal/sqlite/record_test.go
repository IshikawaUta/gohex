package sqlite

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"
)

func TestGetVarint(t *testing.T) {
	cases := []struct {
		in   []byte
		want uint64
		n    int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x7f}, 127, 1},
		{[]byte{0x81, 0x00}, 128, 2},
		{[]byte{0x82, 0x68}, 360, 2},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MaxUint64, 9},
		{[]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 1, 9},
		{[]byte{0x01}, 1, 1},
	}
	for _, c := range cases {
		got, n, err := getVarint(c.in)
		if err != nil {
			t.Errorf("getVarint(%x): %v", c.in, err)
			continue
		}
		if got != c.want || n != c.n {
			t.Errorf("getVarint(%x) = %d,%d want %d,%d", c.in, got, n, c.want, c.n)
		}
	}
	for _, in := range [][]byte{{0x81}, {0x80, 0x80, 0x80}} {
		if _, _, err := getVarint(in); err == nil {
			t.Errorf("getVarint(%x) accepted a truncated varint", in)
		}
	}
}

func TestBeInt(t *testing.T) {
	cases := []struct {
		in   []byte
		want int64
	}{
		{[]byte{0x00}, 0},
		{[]byte{0xff}, -1},
		{[]byte{0x00, 0x01}, 1},
		{[]byte{0xff, 0xfe}, -2},
		{[]byte{0x01, 0x00}, 256},
		{[]byte{0xff, 0xff, 0xff}, -1},
		{[]byte{0x80, 0x00, 0x00}, -8388608},
		{[]byte{0x7f, 0xff, 0xff, 0xff}, 2147483647},
		{[]byte{0xff, 0xff, 0xff, 0xff}, -1},
	}
	for _, c := range cases {
		if got := beInt(c.in); got != c.want {
			t.Errorf("beInt(%x) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestLocalPayload pins the overflow arithmetic to values computed by hand
// from the file format. Changing this function changes where every
// overflowing row ends, so the numbers are spelled out rather than derived.
func TestLocalPayload(t *testing.T) {
	cases := []struct {
		usable, p, want int64
	}{
		{1024, 100, 100},
		{1024, 989, 989},   // exactly X = usable-35
		{1024, 990, 103},   // K = 990 > X, so M = ((1012*32)/255)-23 = 126-23
		{1024, 6405, 285},  // K = 103 + ((6405-103) % 1020) = 103 + 182
		{4096, 4061, 4061}, // X = 4096-35
		{4096, 5000, 908},  // K = 489 + (4511 % 4092) = 489 + 419 <= X
	}
	for _, c := range cases {
		if got := localPayload(c.p, c.usable); got != c.want {
			t.Errorf("localPayload(p=%d, usable=%d) = %d, want %d", c.p, c.usable, got, c.want)
		}
	}
}

func record(t *testing.T, payload []byte) []Value {
	t.Helper()
	db := &DB{textEnc: 1}
	vals, err := db.decodeRecord(payload)
	if err != nil {
		t.Fatalf("decodeRecord(%x): %v", payload, err)
	}
	return vals
}

func TestDecodeRecord(t *testing.T) {
	// header: size 5, serial types NULL, int8, text(2), real
	body := make([]byte, 0, 11)
	body = append(body, 42)
	body = append(body, 'h', 'i')
	var f [8]byte
	binary.BigEndian.PutUint64(f[:], math.Float64bits(2.5))
	body = append(body, f[:]...)
	payload := append([]byte{5, 0, 1, 17, 7}, body...)

	vals := record(t, payload)
	if len(vals) != 4 {
		t.Fatalf("got %d values, want 4", len(vals))
	}
	if !vals[0].IsNull() {
		t.Errorf("value 0 = %v, want NULL", vals[0])
	}
	if vals[1].Int() != 42 {
		t.Errorf("value 1 = %d, want 42", vals[1].Int())
	}
	if vals[2].Text() != "hi" || vals[2].Kind() != KindText {
		t.Errorf("value 2 = %q (kind %d)", vals[2].Text(), vals[2].Kind())
	}
	if vals[3].Float() != 2.5 {
		t.Errorf("value 3 = %v, want 2.5", vals[3].Float())
	}

	// Serial types 8 and 9 are the compact encodings of 0 and 1; 10 and 11
	// are reserved and read as NULL.
	vals = record(t, []byte{6, 8, 9, 10, 11, 13})
	if vals[0].Int() != 0 || vals[1].Int() != 1 {
		t.Errorf("serial 8/9 = %d/%d, want 0/1", vals[0].Int(), vals[1].Int())
	}
	if !vals[2].IsNull() || !vals[3].IsNull() {
		t.Errorf("reserved serial types 10/11 = %v/%v, want NULL/NULL", vals[2], vals[3])
	}
	if vals[4].IsNull() || vals[4].Kind() != KindText {
		t.Errorf("serial 13 = %v (kind %d), want empty text", vals[4], vals[4].Kind())
	}

	// A short record in a table with more columns still decodes; the caller
	// sees NULL for the columns that were never written.
	vals = record(t, []byte{2, 1, 42})
	if len(vals) != 1 || vals[0].Int() != 42 {
		t.Errorf("short record = %+v, want one int 42", vals)
	}
}

func TestDecodeRecordErrors(t *testing.T) {
	db := &DB{textEnc: 1}
	cases := []struct {
		name    string
		payload []byte
		want    string
	}{
		{"header beyond payload", []byte{10, 0}, "claims"},
		{"value beyond body", []byte{2, 6}, "past the end"},
		{"serial type beyond body", []byte{3, 0, 40}, "past the end"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := db.decodeRecord(c.payload)
			if err == nil {
				t.Fatalf("decodeRecord(%x) succeeded, want an error", c.payload)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not contain %q", err, c.want)
			}
		})
	}
}

func TestRowLenAndPath(t *testing.T) {
	db := mustOpen(t, fixture)
	if db.Path() != fixture {
		t.Errorf("Path() = %q, want %q", db.Path(), fixture)
	}
	rows := collect(t, table(t, db, "urls"))
	if rows[0].Len() != len(table(t, db, "urls").Columns) {
		t.Errorf("row carries %d values for %d columns", rows[0].Len(), len(db.byName["urls"].Columns))
	}
	// A short row reports only what it actually holds.
	short := Row{t: db.byName["urls"], rowid: 7, vals: []Value{{kind: KindInt, i: 5}}}
	if short.Len() != 1 {
		t.Errorf("short row Len() = %d, want 1", short.Len())
	}
	if v, ok := short.Get("title"); !ok || !v.IsNull() {
		t.Errorf("short row title = %v (found %v), want NULL", v, ok)
	}
}
