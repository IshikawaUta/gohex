package memory

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// limeBlock writes one LiME header plus a payload whose byte at position i is
// byte(phys+i), so tests can prove Locate maps addresses to the right byte.
func limeBlock(start, end uint64) []byte { // end inclusive
	h := make([]byte, limeHeader)
	copy(h, limeMagic)
	binary.LittleEndian.PutUint32(h[4:], 1)
	binary.LittleEndian.PutUint64(h[8:], start)
	binary.LittleEndian.PutUint64(h[16:], end)
	out := append([]byte(nil), h...)
	for a := start; a <= end; a++ {
		out = append(out, byte(a))
		if a == end { // guard against uint64 overflow on end == MaxUint64
			break
		}
	}
	return out
}

func writeCapture(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLIMEParseAndLocate(t *testing.T) {
	// Three ranges including a one-byte range, a 4 KiB RAM range and a high
	// address; payloads are concatenated header+data blocks.
	blocks := [][]byte{
		limeBlock(0x1000, 0x1003),
		limeBlock(0x40000000, 0x400000FF),
		limeBlock(0xFBD00000, 0xFBD00000),
	}
	var data []byte
	for _, b := range blocks {
		data = append(data, b...)
	}
	c, err := Open(writeCapture(t, "ram.lime", data))
	if err != nil {
		t.Fatal(err)
	}
	if c.Format != FormatLIME {
		t.Fatalf("Format = %q, want lime", c.Format)
	}
	if !c.HasPhys {
		t.Fatal("HasPhys = false, want true")
	}
	if c.Size != int64(len(data)) {
		t.Fatalf("Size = %d, want %d", c.Size, len(data))
	}
	want := []Segment{
		{Index: 0, Offset: 32, Length: 4, PhysStart: 0x1000, PhysEnd: 0x1004},
		{Index: 1, Offset: 32 + 4 + 32, Length: 0x100, PhysStart: 0x40000000, PhysEnd: 0x40000100},
		{Index: 2, Offset: 32 + 4 + 32 + 0x100 + 32, Length: 1, PhysStart: 0xFBD00000, PhysEnd: 0xFBD00001},
	}
	if len(c.Segments) != len(want) {
		t.Fatalf("got %d segments, want %d", len(c.Segments), len(want))
	}
	for i, w := range want {
		if c.Segments[i] != w {
			t.Errorf("segment %d = %+v, want %+v", i, c.Segments[i], w)
		}
	}

	// First, middle and last byte of every segment must map to the payload
	// byte derived from the physical address.
	f, err := os.Open(c.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, phys := range []int64{0x1000, 0x1003, 0x40000000, 0x4000007F, 0x400000FF, 0xFBD00000} {
		loc, err := c.Locate(phys)
		if err != nil {
			t.Fatalf("Locate(%#x): %v", phys, err)
		}
		var b [1]byte
		if _, err := f.ReadAt(b[:], loc.Offset); err != nil {
			t.Fatalf("ReadAt(%#x -> %d): %v", phys, loc.Offset, err)
		}
		if b[0] != byte(phys) {
			t.Errorf("Locate(%#x) -> offset %d holds %#x, want %#x", phys, loc.Offset, b[0], byte(phys))
		}
	}
}

func TestLIMEGapNotCovered(t *testing.T) {
	data := limeBlock(0x1000, 0x1FFF)
	c, err := Open(writeCapture(t, "gap.lime", data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Locate(0x2000); err == nil || !strings.Contains(err.Error(), "not covered") {
		t.Errorf("Locate(end) = %v, want not-covered error", err)
	}
	if _, err := c.Locate(0x0FFF); err == nil || !strings.Contains(err.Error(), "not covered") {
		t.Errorf("Locate(below start) = %v, want not-covered error", err)
	}
}

func TestRAWFallback(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i)
	}
	c, err := Open(writeCapture(t, "ram.raw", data))
	if err != nil {
		t.Fatal(err)
	}
	if c.Format != FormatRAW {
		t.Fatalf("Format = %q, want raw", c.Format)
	}
	if c.HasPhys {
		t.Fatal("HasPhys = true for a raw capture")
	}
	if len(c.Segments) != 1 || c.Segments[0].Offset != 0 || c.Segments[0].Length != 4096 {
		t.Fatalf("segments = %+v, want one full-file segment", c.Segments)
	}
	if _, err := c.Locate(0); err == nil || !strings.Contains(err.Error(), "no physical address map") {
		t.Errorf("Locate on raw = %v, want no-map error", err)
	}
}

func TestOpenErrors(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing.lime")); err == nil || !strings.Contains(err.Error(), "memory:") {
		t.Errorf("Open(missing) = %v, want memory-prefixed error", err)
	}
	if _, err := Open(t.TempDir()); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Errorf("Open(dir) = %v, want directory error", err)
	}
	if _, err := Open(writeCapture(t, "empty.bin", nil)); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("Open(empty) = %v, want empty-capture error", err)
	}
}

func TestLIMEHeaderErrors(t *testing.T) {
	// A valid first block, then a corrupt second header.
	good := limeBlock(0x1000, 0x10FF)

	for _, tc := range []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"truncated-header", []byte(limeMagic + "\x01\x00\x00\x00"), "truncated LiME header"},
		{"bad-magic-second", append(append([]byte(nil), good...), func() []byte {
			b := limeBlock(0x2000, 0x200F)
			b[0] = 'X'
			return b
		}()...), "bad LiME magic"},
		{"unsupported-version", func() []byte {
			b := limeBlock(0x1000, 0x100F)
			binary.LittleEndian.PutUint32(b[4:], 9)
			return b
		}(), "unsupported LiME version"},
		{"inverted-range", func() []byte {
			b := limeBlock(0x1000, 0x100F)
			binary.LittleEndian.PutUint64(b[8:], 0x2000)  // start
			binary.LittleEndian.PutUint64(b[16:], 0x1000) // end < start
			return b
		}(), "beyond end"},
		{"truncated-payload", func() []byte {
			b := limeBlock(0x1000, 0x100F)
			binary.LittleEndian.PutUint64(b[16:], 0x1000000) // claims 16 MiB
			return b
		}(), "payload truncated"},
		{"trailing-junk", append(append([]byte(nil), good...), []byte("junkjunk")...), "truncated LiME header"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Open(writeCapture(t, "bad.lime", tc.data))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestLocateRejectsNegative(t *testing.T) {
	c, err := Open(writeCapture(t, "neg.lime", limeBlock(0x1000, 0x1FFF)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Locate(-1); err == nil {
		t.Error("Locate(-1) = nil, want error")
	}
}
