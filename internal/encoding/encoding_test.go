package bincoding

import (
	"bytes"
	"strings"
	"testing"
)

func TestHexToBytes(t *testing.T) {
	got, err := HexToBytes("4D 5A 90 00")
	if err != nil || !bytes.Equal(got, []byte{0x4D, 0x5A, 0x90, 0x00}) {
		t.Fatalf("spaced = %v, %v", got, err)
	}
	got, err = HexToBytes("0x4d5a9000")
	if err != nil || !bytes.Equal(got, []byte{0x4D, 0x5A, 0x90, 0x00}) {
		t.Fatalf("0x form = %v, %v", got, err)
	}
	got, err = HexToBytes("4D,5A:90-00")
	if err != nil || len(got) != 4 {
		t.Fatalf("separators = %v, %v", got, err)
	}
	if got, err := HexToBytes(""); err != nil || got != nil {
		t.Fatalf("empty = %v, %v", got, err)
	}
	if _, err := HexToBytes("4D5"); err == nil {
		t.Fatal("odd digit count must fail")
	}
	if _, err := HexToBytes("4G"); err == nil {
		t.Fatal("invalid digit must fail")
	}
	if _, err := HexToBytes("zz"); err == nil {
		t.Fatal("invalid digits must fail")
	}
}

func TestBytesToHexRoundTrip(t *testing.T) {
	data := []byte{0x00, 0x0F, 0xF0, 0xFF, 0xA5}
	s := SpacedHex(data)
	if s != "00 0F F0 FF A5" {
		t.Fatalf("SpacedHex = %q", s)
	}
	back, err := HexToBytes(s)
	if err != nil || !bytes.Equal(back, data) {
		t.Fatalf("round trip = %v, %v", back, err)
	}
	if BytesToHex(data, "") != "000FF0FFA5" {
		t.Fatalf("compact = %q", BytesToHex(data, ""))
	}
}

func TestEncodingNames(t *testing.T) {
	for _, e := range All() {
		got, err := ParseEncoding(e.String())
		if err != nil || got != e {
			t.Errorf("ParseEncoding(%q) = %v, %v", e.String(), got, err)
		}
	}
	if _, err := ParseEncoding("Klingon"); err == nil {
		t.Error("unknown encoding should fail")
	}
	if Encoding(99).String() != "unknown" {
		t.Error("unknown encoding name")
	}
}

func TestDecodeEncode(t *testing.T) {
	// ASCII round trip
	s := "Hello, World!"
	for _, enc := range []Encoding{ASCII, UTF8} {
		if back := Decode(enc, Encode(enc, s)); back != s {
			t.Errorf("%v round trip = %q", enc, back)
		}
	}
	// UTF-16 round trip including non-ASCII
	u := "Grüße 漢字 🙂"
	for _, enc := range []Encoding{UTF16LE, UTF16BE} {
		if back := Decode(enc, Encode(enc, u)); back != u {
			t.Errorf("%v round trip = %q", enc, back)
		}
	}
	// EBCDIC round trip
	e := "MAINFRAME-01"
	if back := Decode(EBCDIC, Encode(EBCDIC, e)); back != e {
		t.Errorf("EBCDIC round trip = %q", back)
	}
	// ASCII non-representable → '?'
	if got := Encode(ASCII, "naïve"); string(got) != "na?ve" {
		t.Errorf("ASCII fallback = %q", got)
	}
	// EBCDIC non-representable → '?' (byte 0x6F in CP037)
	if got := Encode(EBCDIC, "日本"); !bytes.Equal(got, []byte{0x6F, 0x6F}) {
		t.Errorf("EBCDIC fallback = %x", got)
	}
	// UTF-8 invalid bytes → U+FFFD, never panics
	if back := Decode(UTF8, []byte{0xFF, 0xFE, 'a'}); !strings.ContainsRune(back, '�') {
		t.Errorf("invalid utf8 = %q", back)
	}
	// ASCII high byte → U+FFFD
	if back := Decode(ASCII, []byte{0xC3, 0xA9}); strings.ContainsRune(back, 'Ã') {
		t.Errorf("ascii high = %q", back)
	}
}

func TestColumnText(t *testing.T) {
	if got := ColumnText(ASCII, []byte("AB\x00\x1f\x7f~")); got != "AB...~" {
		t.Errorf("ascii column = %q", got)
	}
	if got := ColumnText(EBCDIC, Encode(EBCDIC, "Hi\x00")); !strings.HasPrefix(got, "Hi") {
		t.Errorf("ebcdic column = %q", got)
	}
	if got := ColumnText(UTF16LE, Encode(UTF16LE, "A B")); got != "A B" {
		t.Errorf("utf16 column = %q", got)
	}
}

func TestIntelHexRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte{1, 2, 3, 4}, 1000) // 4000 bytes → multiple records
	enc := EncodeIntelHex(data, 0x1000)
	if !strings.Contains(enc, ":10") {
		t.Fatalf("no data records: %q", enc[:80])
	}
	img, err := DecodeIntelHex(strings.NewReader(enc))
	if err != nil {
		t.Fatal(err)
	}
	if !img.EOF || img.Origin != 0x1000 {
		t.Fatalf("meta: origin=%#x eof=%v", img.Origin, img.EOF)
	}
	if !bytes.Equal(img.Data, data) {
		t.Fatalf("round trip mismatch: %d vs %d bytes", len(img.Data), len(data))
	}
}

func TestIntelHexExtendedAddress(t *testing.T) {
	// Data at absolute 0x00010000 via extended linear address record.
	enc := ":020000040001F9\n:0400000001020304F2\n:00000001FF\n"
	img, err := DecodeIntelHex(strings.NewReader(enc))
	if err != nil {
		t.Fatal(err)
	}
	if img.Origin != 0x10000 {
		t.Fatalf("origin = %#x", img.Origin)
	}
	if !bytes.Equal(img.Data, []byte{1, 2, 3, 4}) {
		t.Fatalf("data = %v", img.Data)
	}
}

func TestIntelHexErrors(t *testing.T) {
	cases := []string{
		"41000000FF\n",    // missing ':'
		":0100000041BF\n", // checksum off by one
		":0100000400\n",   // length mismatch
		":010000770088\n", // unknown record type
		":00000000FF\n",   // never terminates with an EOF record
	}
	for i, c := range cases {
		if _, err := DecodeIntelHex(strings.NewReader(c)); err == nil {
			t.Errorf("case %d (%q): expected error", i, c)
		}
	}
}

func TestSRecordRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte{0xAA, 0x55}, 500)
	enc := EncodeSRecords(data, 0x0100)
	if !strings.HasPrefix(enc, "S0") {
		t.Fatalf("missing header: %q", enc[:40])
	}
	img, err := DecodeSRecords(strings.NewReader(enc))
	if err != nil {
		t.Fatal(err)
	}
	if img.Origin != 0x0100 || !bytes.Equal(img.Data, data) {
		t.Fatalf("round trip: origin=%#x len=%d want %d", img.Origin, len(img.Data), len(data))
	}
}

func TestSRecordAddressWidths(t *testing.T) {
	for typ, want := range map[byte]int{'0': 2, '1': 2, '2': 3, '3': 4, '5': 2, '7': 4, '8': 3, '9': 2} {
		if got := SRecordAddressWidth(typ); got != want {
			t.Errorf("S%c width = %d, want %d", typ, got, want)
		}
	}
	if SRecordAddressWidth('X') != 0 {
		t.Error("unknown width")
	}
}

func TestSRecordErrors(t *testing.T) {
	cases := []string{
		"X1030000F901\n", // missing S
		"S1030000F9\n",   // bad checksum
		"SZ030000F9\n",   // unknown type
		"S1030000F9\n",   // no termination
		"S5",             // truncated
	}
	for i, c := range cases {
		if _, err := DecodeSRecords(strings.NewReader(c)); err == nil {
			t.Errorf("case %d (%q): expected error", i, c)
		}
	}
}
