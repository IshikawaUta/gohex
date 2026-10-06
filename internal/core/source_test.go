package core

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFileSourceReadAt(t *testing.T) {
	data := []byte("0123456789ABCDEF")
	p := writeTemp(t, "a.bin", data)
	src, err := OpenFile(p)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	if src.Size() != int64(len(data)) {
		t.Fatalf("size = %d, want %d", src.Size(), len(data))
	}
	if src.Name() != p {
		t.Fatalf("name = %q", src.Name())
	}

	buf := make([]byte, 4)
	n, err := src.ReadAt(buf, 6)
	if err != nil || n != 4 || string(buf) != "6789" {
		t.Fatalf("ReadAt = %q, %v, n=%d", buf, err, n)
	}

	// Partial tail read must report io.EOF per io.ReaderAt contract.
	n, err = src.ReadAt(buf, 14)
	if n != 2 || !errors.Is(err, io.EOF) || string(buf[:2]) != "EF" {
		t.Fatalf("tail ReadAt = %q, %v, n=%d", buf, err, n)
	}

	// Read at/after end: 0 bytes + EOF.
	n, err = src.ReadAt(buf, 16)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("end ReadAt n=%d err=%v", n, err)
	}

	// Negative offset.
	if _, err := src.ReadAt(buf, -1); !errors.Is(err, ErrNegativeOffset) {
		t.Fatalf("want ErrNegativeOffset, got %v", err)
	}
}

func TestOpenFileErrors(t *testing.T) {
	if _, err := OpenFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error for missing file")
	}
	if _, err := OpenFile(t.TempDir()); err == nil {
		t.Fatal("expected error for directory")
	}
}

func TestOpenFallbackAndMapped(t *testing.T) {
	data := bytes.Repeat([]byte{0xAA, 0x55}, 1000)
	p := writeTemp(t, "m.bin", data)

	src, err := Open(p, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	got, err := ReadWindow(src, 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data[:16]) {
		t.Fatalf("mapped window mismatch: %x", got)
	}

	// Limit smaller than file forces stream fallback (still correct reads).
	src2, err := Open(p, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer src2.Close()
	got, err = ReadWindow(src2, 100, 8)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data[100:108]) {
		t.Fatalf("fallback window mismatch: %x", got)
	}
}

func TestReadWindowClamps(t *testing.T) {
	data := []byte("hello world")
	p := writeTemp(t, "w.bin", data)
	src, err := OpenFile(p)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	got, err := ReadWindow(src, 6, 1000) // clamp to end
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "world" {
		t.Fatalf("clamp = %q", got)
	}

	if _, err := ReadWindow(src, 99, 10); !errors.Is(err, ErrOutOfBounds) {
		t.Fatalf("want ErrOutOfBounds, got %v", err)
	}
	if _, err := ReadWindow(src, -5, 10); !errors.Is(err, ErrNegativeOffset) {
		t.Fatalf("want ErrNegativeOffset, got %v", err)
	}
	if got, err := ReadWindow(src, 0, 0); err != nil || got != nil {
		t.Fatalf("zero read = %v, %v", got, err)
	}
	if got, err := ReadWindow(src, 0, MaxWindow+1); err != nil || len(got) != len(data) {
		t.Fatalf("max clamp = %d, %v", len(got), err)
	}
}

func TestParseOffset(t *testing.T) {
	cases := []struct {
		in    string
		base  OffsetBase
		ref   int64
		sec   int64
		want  int64
		wantE bool
	}{
		{"0x1A", BaseHex, 0, 0, 26, false},
		{"1A", BaseHex, 0, 0, 26, false},
		{"1A", BaseDec, 0, 0, 0, true}, // "1A" invalid in decimal
		{"10", BaseDec, 0, 0, 10, false},
		{"$1F", BaseHex, 0, 0, 31, false},
		{"+10", BaseHex, 100, 0, 116, false},
		{"-10", BaseHex, 100, 0, 84, false},
		{"1KB", BaseHex, 0, 0, 1024, false},
		{"1.5MB", BaseHex, 0, 0, 1572864, false},
		{"1GB", BaseHex, 0, 0, 1073741824, false},
		{"2TB", BaseHex, 0, 0, 2199023255552, false},
		{"100s", BaseHex, 0, 512, 51200, false},
		{"-5", BaseHex, 3, 0, 0, true}, // resolves negative
		{"", BaseHex, 0, 0, 0, true},
		{"zz", BaseHex, 0, 0, 0, true},
		{"0xzz", BaseHex, 0, 0, 0, true},
		{"5xs", BaseHex, 0, 512, 0, true}, // bad sector number
		{"1KBs", BaseHex, 0, 512, 0, true},
		{"1KB", BaseHex, 0, 0, 1024, false},
		{"-1KB", BaseHex, 5000, 0, 3976, false},
		{"  0x10  ", BaseHex, 0, 0, 16, false},
	}
	for _, c := range cases {
		got, err := ParseOffset(c.in, c.base, c.ref, c.sec)
		if c.wantE {
			if err == nil {
				t.Errorf("ParseOffset(%q) = %d, want error", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("ParseOffset(%q) = %d, %v; want %d", c.in, got, err, c.want)
		}
	}

	// Sector suffix without sector size must fail.
	if _, err := ParseOffset("10s", BaseHex, 0, 0); err == nil {
		t.Error("sector offset without size should fail")
	}
}

func TestFormatOffset(t *testing.T) {
	if s := FormatOffset(255, BaseHex, 8); s != "000000FF" {
		t.Errorf("hex format = %q", s)
	}
	if s := FormatOffset(255, BaseDec, 6); s != "   255" {
		t.Errorf("dec format = %q", s)
	}
	if s := FormatOffset(1, BaseHex, 0); s != "00000001" {
		t.Errorf("default width = %q", s)
	}
}
