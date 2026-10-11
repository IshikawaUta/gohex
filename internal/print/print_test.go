package print

import (
	"bytes"
	"image/png"
	"strings"
	"testing"
)

func TestLines(t *testing.T) {
	data := []byte("Hello, hex world!123")
	got := Lines(data, 0x1000)
	if len(got) != 2 {
		t.Fatalf("lines = %d, want 2: %q", len(got), got)
	}
	want0 := "00001000   48 65 6c 6c 6f 2c 20 68  65 78 20 77 6f 72 6c 64  |Hello, hex world|"
	if got[0] != want0 {
		t.Errorf("line0 = %q\nwant      %q", got[0], want0)
	}
	// Second line is the short tail: padded hex columns, closed gutter.
	if !strings.HasPrefix(got[1], "00001010   21 31 32 33") || !strings.HasSuffix(got[1], "|!123|") {
		t.Errorf("line1 = %q", got[1])
	}

	// Non-printables render as dots, never raw bytes.
	got = Lines([]byte{0x00, 0x1f, 0x7f, 0xff}, 0)
	if !strings.Contains(got[0], "|....|") {
		t.Errorf("non-printables = %q", got[0])
	}

	if len(Lines(nil, 0)) != 0 {
		t.Error("empty data produced lines")
	}
}

func TestPDF(t *testing.T) {
	lines := Lines(bytes.Repeat([]byte{0xAA}, 64), 0)
	var buf bytes.Buffer
	if err := PDF(&buf, "case-1 image.dd [0, 64)", lines); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()
	if !bytes.HasPrefix(out, []byte("%PDF-1.4")) {
		t.Fatalf("not a PDF: %q", out[:20])
	}
	if !bytes.Contains(out, []byte("%%EOF")) {
		t.Error("missing EOF marker")
	}
	if !bytes.Contains(out, []byte("/BaseFont /Courier")) {
		t.Error("grid must use fixed-pitch Courier")
	}
	if !bytes.Contains(out, []byte("00000000")) {
		t.Error("offsets missing from content")
	}
	// Titles with control characters must not break the content stream.
	buf.Reset()
	if err := PDF(&buf, "bad\x00title\n", nil); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("bad\x00title")) {
		t.Error("control byte leaked into the PDF string")
	}
}

func TestPDFPaginates(t *testing.T) {
	// 200 lines at 58 lines/page must produce at least 4 pages.
	lines := make([]string, 200)
	for i := range lines {
		lines[i] = strings.Repeat("x", 75)
	}
	var buf bytes.Buffer
	if err := PDF(&buf, "long", lines); err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(buf.Bytes(), []byte("/Type /Page ")); n < 4 {
		t.Errorf("page objects = %d, want >= 4", n)
	}
}

func TestPNG(t *testing.T) {
	lines := Lines(bytes.Repeat([]byte{0x41}, 48), 0x20)
	var buf bytes.Buffer
	if err := PNG(&buf, "selection 0x20", lines); err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("PNG decode: %v", err)
	}
	b := img.Bounds()
	// 16*2 margin + title area + 3 lines * 13px
	if b.Dy() < 16*2+28+3*13 {
		t.Errorf("height = %d, too short for 3 lines + title", b.Dy())
	}
	if b.Dx() < 75*7 {
		t.Errorf("width = %d, too narrow for the grid", b.Dx())
	}
}

func TestPNGEmptyLines(t *testing.T) {
	var buf bytes.Buffer
	if err := PNG(&buf, "t", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := png.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("empty-lines PNG decode: %v", err)
	}
}

func TestMaxLinesConstant(t *testing.T) {
	// Guard the PNG ceiling: 4000 lines * 13 px must stay under 65535.
	if MaxLines*13 >= 65535 {
		t.Errorf("MaxLines*13 = %d overflows PNG dimension cap", MaxLines*13)
	}
}
