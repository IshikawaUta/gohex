package recovery

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// memStream is an in-memory read-only Stream, the same contract core.Source
// provides for real evidence.
type memStream struct{ b []byte }

func (m *memStream) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m.b)) {
		return 0, io.EOF
	}
	n := copy(p, m.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *memStream) Size() int64 { return int64(len(m.b)) }

// pad returns n bytes that deliberately avoid every signature the registry
// looks for (no 0x00 pairs, no magic numbers).
func pad(n int) []byte {
	if n < 0 {
		n = 0
	}
	return bytes.Repeat([]byte{0x20}, n)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func u16le(v uint16) []byte {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	return b[:]
}

func u32le(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

func u32be(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

// fakeJPEG builds a plausible JPEG: SOI, APP0 segment, filler, EOI.
func fakeJPEG(payload int) []byte {
	hdr := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00}
	body := bytes.Repeat([]byte{0x21}, payload)
	return concat(hdr, body, []byte{0xFF, 0xD9})
}

// fakePNG builds a PNG-shaped object: 8-byte signature, filler, IEND footer.
func fakePNG(payload int) []byte {
	hdr := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	body := bytes.Repeat([]byte{'A'}, payload)
	return concat(hdr, body, []byte{'I', 'E', 'N', 'D', 0xAE, 0x42, 0x60, 0x82})
}

func fakeGIF(payload int) []byte {
	hdr := []byte{'G', 'I', 'F', '8', '9', 'a'}
	return concat(hdr, pad(payload), []byte{0x00, 0x3B})
}

func fakePDF(payload int) []byte {
	return concat([]byte("%PDF-1.7\n"), pad(payload), []byte("%%EOF"), []byte{0x0A})
}

func fakeZIP(payload int) []byte {
	local := concat(
		[]byte{'P', 'K', 0x03, 0x04},
		[]byte{0x14, 0x00}, // version needed (20)
		[]byte{0x00, 0x00}, // flags
		[]byte{0x08, 0x00}, // deflate
		pad(16),            // mtime, mdate, crc, csize, usize
		[]byte{0x05, 0x00}, // file name length
		[]byte{0x00, 0x00}, // extra field length
		[]byte("a.txt"),
	)
	// A real end-of-central-directory record: 22 bytes with comment length 0.
	eocd := concat(
		[]byte{'P', 'K', 0x05, 0x06},
		u16le(0), u16le(0), // disk numbers
		u16le(1), u16le(1), // entries
		u32le(0), u32le(0), // central directory size/offset
		u16le(0), // comment length
	)
	return concat(local, pad(payload), eocd)
}

func fakeBMP(total int) []byte {
	b := make([]byte, total)
	b[0], b[1] = 'B', 'M'
	binary.LittleEndian.PutUint32(b[2:6], uint32(total))
	binary.LittleEndian.PutUint32(b[10:14], 54)
	binary.LittleEndian.PutUint32(b[14:18], 40)
	for i := 18; i < total; i++ {
		b[i] = 0x30
	}
	return b
}

func fakeRIFF(form string, total int) []byte {
	b := make([]byte, total)
	copy(b, "RIFF")
	binary.LittleEndian.PutUint32(b[4:8], uint32(total-8))
	copy(b[8:12], form)
	for i := 12; i < total; i++ {
		b[i] = 0x31
	}
	return b
}

// fakeMP4 builds an ftyp+moov file. The walker must skip moov in one step and
// report the concatenated size.
func fakeMP4(ftypSize, moovSize int) []byte {
	b := make([]byte, ftypSize+moovSize)
	copy(b, u32be(uint32(ftypSize)))
	copy(b[4:8], "ftyp")
	copy(b[8:12], "isom")
	copy(b[16:20], "isom")
	copy(b[20:24], "iso2")
	copy(b[ftypSize:], u32be(uint32(moovSize)))
	copy(b[ftypSize+4:ftypSize+8], "moov")
	return b
}

// carveOne asserts exactly one result and returns it.
func carveOne(t *testing.T, src Stream, opts Options) Carved {
	t.Helper()
	got, err := Carve(src, opts)
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want exactly 1 result, got %d: %+v", len(got), got)
	}
	return got[0]
}

func TestCarveEachType(t *testing.T) {
	tests := []struct {
		name  string
		types []string
		want  string
		data  []byte
	}{
		{"jpeg", nil, "jpeg", fakeJPEG(400)},
		{"png", nil, "png", fakePNG(400)},
		{"gif", nil, "gif", fakeGIF(400)},
		{"pdf", nil, "pdf", fakePDF(400)},
		{"zip", nil, "zip", fakeZIP(400)},
		{"bmp", nil, "bmp", fakeBMP(400)},
		{"wav", nil, "wav", fakeRIFF("WAVE", 400)},
		{"avi", nil, "avi", fakeRIFF("AVI ", 400)},
		{"mp4", nil, "mp4", fakeMP4(32, 368)},
		{"filtered png", []string{"png"}, "png", fakePNG(400)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := carveOne(t, &memStream{tc.data}, Options{Types: tc.types})
			if got.Type != tc.want {
				t.Errorf("Type = %q, want %q", got.Type, tc.want)
			}
			if got.Offset != 0 {
				t.Errorf("Offset = %d, want 0", got.Offset)
			}
			if want := int64(len(tc.data)); got.Length != want {
				t.Errorf("Length = %d, want %d", got.Length, want)
			}
			if got.Truncated {
				t.Error("Truncated = true, want false")
			}
			if got.HeaderLen < 1 {
				t.Errorf("HeaderLen = %d, want >= 1", got.HeaderLen)
			}
			if got.Index != 0 {
				t.Errorf("Index = %d, want 0", got.Index)
			}
		})
	}
}

func TestCarveMultipleAscending(t *testing.T) {
	var data []byte
	data = append(data, pad(64)...)
	jpegAt := len(data)
	data = append(data, fakeJPEG(200)...)
	data = append(data, pad(64)...)
	pngAt := len(data)
	data = append(data, fakePNG(200)...)
	data = append(data, pad(64)...)
	zipAt := len(data)
	data = append(data, fakeZIP(200)...)
	data = append(data, pad(64)...)
	bmpAt := len(data)
	data = append(data, fakeBMP(200)...)

	got, err := Carve(&memStream{data}, Options{})
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	want := []struct {
		typ    string
		offset int
	}{
		{"jpeg", jpegAt}, {"png", pngAt}, {"zip", zipAt}, {"bmp", bmpAt},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d results, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Type != w.typ || got[i].Offset != int64(w.offset) || got[i].Index != i {
			t.Errorf("[%d] = %s@%#x idx %d, want %s@%#x idx %d",
				i, got[i].Type, got[i].Offset, got[i].Index, w.typ, w.offset, i)
		}
	}
}

// A file nested inside another carved object must not be reported on its own.
func TestCarveNestedHeaderSkipped(t *testing.T) {
	inner := fakePNG(50)
	outer := concat(
		[]byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00},
		pad(100), inner, pad(100),
		[]byte{0xFF, 0xD9},
	)
	got, err := Carve(&memStream{outer}, Options{Types: []string{"jpeg", "png"}})
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(got), got)
	}
	if got[0].Type != "jpeg" || got[0].Length != int64(len(outer)) {
		t.Errorf("got %s len %d, want jpeg len %d", got[0].Type, got[0].Length, len(outer))
	}
}

func TestCarveRejectsFalsePositives(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"jpeg invalid first marker", concat([]byte{0xFF, 0xD8, 0xFF, 0x00}, pad(300), []byte{0xFF, 0xD9})},
		{"jpeg no marker run", concat([]byte{0xFF, 0xD8, 0xFF, 0xFF}, pad(300))},
		{"gif wrong version", concat([]byte("GIF8xx"), pad(300), []byte{0x00, 0x3B})},
		{"zip bad compression method", concat(
			[]byte{'P', 'K', 0x03, 0x04}, []byte{0x14, 0x00, 0x00, 0x00},
			[]byte{0x63, 0x00}, pad(300))},
		{"bmp absurd size", concat([]byte{'B', 'M'}, []byte{0x01, 0x02, 0x03, 0x04}, pad(300))},
		{"bmp unknown dib header", concat([]byte{'B', 'M'}, u32le(200), u32le(0), u32le(54), u32le(0x0BAD), pad(300))},
		{"riff unknown form", concat([]byte("RIFF"), u32le(300), []byte("XXXX"), pad(300))},
		{"prose only", []byte("The BM in IBM and the PK in packet are not files.")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Carve(&memStream{tc.data}, Options{AllowTruncated: true})
			if err != nil {
				t.Fatalf("Carve: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("want no results, got %+v", got)
			}
		})
	}
}

func TestCarveTruncatedCandidate(t *testing.T) {
	data := concat(
		[]byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00},
		pad(300),
	)
	src := &memStream{data}
	if got, err := Carve(src, Options{Types: []string{"jpeg"}}); err != nil || len(got) != 0 {
		t.Fatalf("want no results without AllowTruncated, got %+v (err %v)", got, err)
	}
	got := carveOne(t, src, Options{Types: []string{"jpeg"}, AllowTruncated: true})
	if !got.Truncated || got.Length != int64(len(data)) {
		t.Errorf("got truncated=%v len=%d, want true len=%d", got.Truncated, got.Length, len(data))
	}
}

// A footer past the per-object cap is never a truncation: the cap bound the
// search, not the end of the evidence.
func TestCarveMaxSizeCap(t *testing.T) {
	data := fakeJPEG(300)
	src := &memStream{data}
	opts := Options{Types: []string{"jpeg"}, MaxSize: 50, AllowTruncated: true}
	got, err := Carve(src, opts)
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want no results, got %+v", got)
	}
}

func TestCarveMaxResults(t *testing.T) {
	var data []byte
	for i := 0; i < 5; i++ {
		data = append(data, pad(32)...)
		data = append(data, fakePNG(80)...)
	}
	all, err := Carve(&memStream{data}, Options{Types: []string{"png"}})
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("want 5 results, got %d", len(all))
	}
	capped, err := Carve(&memStream{data}, Options{Types: []string{"png"}, Max: 2})
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if len(capped) != 2 {
		t.Fatalf("want 2 results with Max=2, got %d", len(capped))
	}
}

// A header that straddles a scan window must be matched exactly once, and its
// footer (found in the next window) must still close the object.
func TestCarveAcrossWindowBoundary(t *testing.T) {
	obj := fakePNG(100)
	off := scanWindow - 3 // signature starts 3 bytes before the boundary
	data := bytes.Repeat([]byte{0x20}, scanWindow+2000)
	copy(data[off:], obj)

	got := carveOne(t, &memStream{data}, Options{Types: []string{"png"}})
	if got.Offset != int64(off) {
		t.Errorf("Offset = %d, want %d", got.Offset, off)
	}
	if want := int64(len(obj)); got.Length != want {
		t.Errorf("Length = %d, want %d", got.Length, want)
	}
}

// The same object placed exactly on the boundary must behave identically.
func TestCarveHeaderOnWindowBoundary(t *testing.T) {
	obj := fakePNG(100)
	data := bytes.Repeat([]byte{0x20}, scanWindow+2000)
	copy(data[scanWindow:], obj)

	got := carveOne(t, &memStream{data}, Options{Types: []string{"png"}})
	if got.Offset != scanWindow || got.Length != int64(len(obj)) {
		t.Errorf("got %#x+%d, want %#x+%d", got.Offset, got.Length, scanWindow, len(obj))
	}
}

func TestCarveProgress(t *testing.T) {
	data := bytes.Repeat([]byte{0x20}, scanWindow+64)
	copy(data[10:], fakePNG(50))
	var calls int
	var lastDone, lastTotal int64
	opts := Options{
		Types: []string{"png"},
		Progress: func(done, total int64) {
			calls++
			lastDone, lastTotal = done, total
		},
	}
	if _, err := Carve(&memStream{data}, opts); err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if calls < 2 {
		t.Errorf("Progress called %d times, want >= 2 (two windows)", calls)
	}
	if lastDone != int64(len(data)) || lastTotal != int64(len(data)) {
		t.Errorf("final progress = %d/%d, want %d/%d", lastDone, lastTotal, len(data), len(data))
	}
}

func TestCarveEdgeCases(t *testing.T) {
	if _, err := Carve(nil, Options{}); err == nil {
		t.Error("Carve(nil) = nil error, want error")
	}
	if got, err := Carve(&memStream{nil}, Options{}); err != nil || got != nil {
		t.Errorf("empty source = %v, %v; want nil, nil", got, err)
	}
	if got, err := Carve(&memStream{fakePNG(50)}, Options{From: 10, To: 5}); err != nil || got != nil {
		t.Errorf("inverted range = %v, %v; want nil, nil", got, err)
	}
	// A negative start is clamped to the beginning rather than rejected.
	data := fakePNG(50)
	if got := carveOne(t, &memStream{data}, Options{From: -1, Types: []string{"png"}}); got.Offset != 0 {
		t.Errorf("Offset = %d, want 0", got.Offset)
	}
	// Scanning a range that excludes the object finds nothing.
	if got, err := Carve(&memStream{data}, Options{From: int64(len(data))}); err != nil || len(got) != 0 {
		t.Errorf("range past the object = %v, %v; want empty", got, err)
	}
	// An unknown type is an error, not a silent empty run.
	if _, err := Carve(&memStream{data}, Options{Types: []string{"nope"}}); err == nil {
		t.Error("unknown type = nil error, want error")
	}
}

func TestTypesAndHasType(t *testing.T) {
	list := Types()
	if len(list) != len(registry) {
		t.Fatalf("Types() = %d entries, want %d", len(list), len(registry))
	}
	seen := map[string]bool{}
	for _, ti := range list {
		if ti.Name == "" || ti.Display == "" || ti.Ext == "" {
			t.Errorf("incomplete SpecInfo: %+v", ti)
		}
		if seen[ti.Name] {
			t.Errorf("duplicate type %q", ti.Name)
		}
		seen[ti.Name] = true
		if ti.Extent != "footer" && ti.Extent != "length" {
			t.Errorf("Extent = %q, want footer|length", ti.Extent)
		}
	}
	if !HasType("JPEG ") || !HasType("png") {
		t.Error("HasType should be case- and space-insensitive")
	}
	if HasType("nope") {
		t.Error("HasType(nope) = true, want false")
	}
}

func TestExtract(t *testing.T) {
	png := fakePNG(300)
	src := &memStream{png}
	c := carveOne(t, src, Options{Types: []string{"png"}})

	var buf bytes.Buffer
	n, err := Extract(src, c, &buf)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if n != int64(len(png)) || !bytes.Equal(buf.Bytes(), png) {
		t.Errorf("Extract wrote %d bytes, equal=%v; want %d bytes, equal=true",
			n, bytes.Equal(buf.Bytes(), png), len(png))
	}

	if _, err := Extract(src, Carved{Offset: 10, Length: 1 << 20}, &buf); err == nil {
		t.Error("range past the end = nil error, want error")
	}
	if _, err := Extract(src, Carved{Offset: -1, Length: 4}, &buf); err == nil {
		t.Error("negative offset = nil error, want error")
	}
	if _, err := Extract(nil, c, &buf); err == nil {
		t.Error("nil stream = nil error, want error")
	}
	if _, err := Extract(src, c, nil); err == nil {
		t.Error("nil writer = nil error, want error")
	}
	if n, err := Extract(src, Carved{}, &buf); err != nil || n != 0 {
		t.Errorf("zero length = %d, %v; want 0, nil", n, err)
	}
}

func TestBMPLength(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantOK     bool
		wantLength int64
	}{
		{"valid 200 byte bitmap", fakeBMP(200), true, 200},
		{"bad signature", append([]byte{'X', 'M'}, pad(64)...), false, 0},
		{"reserved words set", func() []byte {
			b := fakeBMP(200)
			b[7] = 0x01
			return b
		}(), false, 0},
		{"unknown dib header", func() []byte {
			b := fakeBMP(200)
			binary.LittleEndian.PutUint32(b[14:18], 99)
			return b
		}(), false, 0},
		{"pixel offset past size", func() []byte {
			b := fakeBMP(200)
			binary.LittleEndian.PutUint32(b[10:14], 5000)
			return b
		}(), false, 0},
		{"size below header", func() []byte {
			b := fakeBMP(200)
			binary.LittleEndian.PutUint32(b[2:6], 20)
			return b
		}(), false, 0},
		{"header runs past source", append([]byte{'B', 'M'}, pad(4)...), false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _, ok := bmpLength(&memStream{tc.data}, 0)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (length %d)", ok, tc.wantOK, got)
			}
			if ok && got != tc.wantLength {
				t.Errorf("length = %d, want %d", got, tc.wantLength)
			}
		})
	}
}

func TestRIFFLength(t *testing.T) {
	wav := fakeRIFF("WAVE", 128)
	if got, trunc, ok := riffLength("WAVE")(&memStream{wav}, 0); !ok || got != 128 || trunc {
		t.Errorf("wave = (%d, %v, %v), want (128, false, true)", got, trunc, ok)
	}
	if _, _, ok := riffLength("WAVE")(&memStream{fakeRIFF("AVI ", 128)}, 0); ok {
		t.Error("WAVE parser accepted an AVI form")
	}
	if _, _, ok := riffLength("AVI ")(&memStream{fakeRIFF("AVI ", 128)}, 0); !ok {
		t.Error("AVI parser rejected its own form")
	}
	// 0xFFFFFFFF is the streaming convention: the object runs to the end.
	stream := fakeRIFF("WAVE", 64)
	binary.LittleEndian.PutUint32(stream[4:8], 0xFFFFFFFF)
	got, trunc, ok := riffLength("WAVE")(&memStream{stream}, 0)
	if !ok || !trunc || got != 64 {
		t.Errorf("streaming wave = (%d, %v, %v), want (64, true, true)", got, trunc, ok)
	}
	if _, _, ok := riffLength("WAVE")(&memStream{[]byte("RIFX")}, 0); ok {
		t.Error("RIFF parser accepted a bad signature")
	}
}

func TestMP4Length(t *testing.T) {
	got, trunc, ok := mp4Length(&memStream{fakeMP4(32, 64)}, 0)
	if !ok || trunc || got != 96 {
		t.Errorf("valid mp4 = (%d, %v, %v), want (96, false, true)", got, trunc, ok)
	}
	// The ftyp box must be small; a huge first size field is random data.
	big := fakeMP4(32, 64)
	binary.BigEndian.PutUint32(big[0:4], 0x7FFFFFFF)
	if _, _, ok := mp4Length(&memStream{big}, 0); ok {
		t.Error("accepted an implausible ftyp size")
	}
	// A non-printable box type after ftyp rejects the walk.
	bad := fakeMP4(32, 64)
	bad[36] = 0x01
	if _, _, ok := mp4Length(&memStream{bad}, 0); ok {
		t.Error("accepted a non-printable box type")
	}
	// A box that runs past the source is truncated rather than rejected.
	short := fakeMP4(32, 64)
	binary.BigEndian.PutUint32(short[32:36], 4096)
	got, trunc, ok = mp4Length(&memStream{short}, 0)
	if !ok || !trunc || got != 96 {
		t.Errorf("overlong box = (%d, %v, %v), want (96, true, true)", got, trunc, ok)
	}
	if _, _, ok := mp4Length(&memStream{[]byte("ftyp")}, 0); ok {
		t.Error("accepted a source shorter than a box header")
	}
}

func TestFormatValidators(t *testing.T) {
	tests := []struct {
		name string
		fn   func(Stream, int64) bool
		ok   []byte
		bad  []byte
	}{
		{"jpeg", jpegOK, []byte{0xFF, 0xD8, 0xFF, 0xE0}, []byte{0xFF, 0xD8, 0xFF, 0xD9}},
		{"gif", gifOK, []byte("GIF87a"), []byte("GIF87b")},
		{"zip", zipOK, concat(
			[]byte{'P', 'K', 0x03, 0x04}, []byte{0x14, 0x00, 0x00, 0x00, 0x08, 0x00}),
			concat([]byte{'P', 'K', 0x03, 0x04}, []byte{0x14, 0x00, 0x00, 0x00, 0xFF, 0x00})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.fn(&memStream{tc.ok}, 0) {
				t.Error("rejected valid header")
			}
			if tc.fn(&memStream{tc.bad}, 0) {
				t.Error("accepted invalid header")
			}
			if tc.fn(&memStream{[]byte{0x00}}, 0) {
				t.Error("accepted a source shorter than the header")
			}
		})
	}
}

// High-entropy data must not produce an unbounded queue or any result: the
// structural validators are what keep random bytes out of the report.
func TestCarveIgnoresRandomData(t *testing.T) {
	data := make([]byte, 1<<20)
	seed := uint32(0x12345678)
	for i := range data {
		seed = seed*1664525 + 1013904223
		data[i] = byte(seed >> 24)
	}
	got, err := Carve(&memStream{data}, Options{AllowTruncated: true})
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want no results from random data, got %d: %+v", len(got), got)
	}
}
