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

// memRegion is one address range with payload bytes derived from the address.
type memRegion struct {
	addr uint64
	data []byte
}

// payloadFor builds a region whose byte at position i is byte(addr+i).
func payloadFor(addr uint64, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(addr + uint64(i))
	}
	return b
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
	if !c.HasMap {
		t.Fatal("HasMap = false, want true")
	}
	if c.Size != int64(len(data)) {
		t.Fatalf("Size = %d, want %d", c.Size, len(data))
	}
	want := []Segment{
		{Index: 0, Offset: 32, Length: 4, AddrStart: 0x1000, AddrEnd: 0x1004},
		{Index: 1, Offset: 32 + 4 + 32, Length: 0x100, AddrStart: 0x40000000, AddrEnd: 0x40000100},
		{Index: 2, Offset: 32 + 4 + 32 + 0x100 + 32, Length: 1, AddrStart: 0xFBD00000, AddrEnd: 0xFBD00001},
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
	if c.HasMap {
		t.Fatal("HasMap = true for a raw capture")
	}
	if len(c.Segments) != 1 || c.Segments[0].Offset != 0 || c.Segments[0].Length != 4096 {
		t.Fatalf("segments = %+v, want one full-file segment", c.Segments)
	}
	if _, err := c.Locate(0); err == nil || !strings.Contains(err.Error(), "no address map") {
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

// --- ELF core builders and tests -------------------------------------------

// buildELFCore assembles a 64-bit little-endian ELF core: header, one
// PT_LOAD per region plus a trailing PT_NOTE, then the payloads.
func buildELFCore(regions []memRegion) []byte {
	nph := len(regions) + 1
	phoff := elfEhdr64
	dataOff := phoff + nph*elfPhdr64
	offs := make([]int, len(regions))
	cur := dataOff
	for i, r := range regions {
		offs[i] = cur
		cur += len(r.data)
	}

	ehdr := make([]byte, elfEhdr64)
	ehdr[0], ehdr[1], ehdr[2], ehdr[3] = 0x7F, 'E', 'L', 'F'
	ehdr[4] = elfClass64
	ehdr[5] = elfDataLE
	ehdr[6] = 1
	binary.LittleEndian.PutUint16(ehdr[16:], elfTypeCore)
	binary.LittleEndian.PutUint16(ehdr[18:], 62) // EM_X86_64
	binary.LittleEndian.PutUint32(ehdr[20:], 1)
	binary.LittleEndian.PutUint64(ehdr[32:], uint64(phoff))
	binary.LittleEndian.PutUint16(ehdr[52:], elfEhdr64)
	binary.LittleEndian.PutUint16(ehdr[54:], elfPhdr64)
	binary.LittleEndian.PutUint16(ehdr[56:], uint16(nph))

	phdrs := make([]byte, nph*elfPhdr64)
	for i, r := range regions {
		p := phdrs[i*elfPhdr64:]
		binary.LittleEndian.PutUint32(p[0:], elfPTLoad)
		binary.LittleEndian.PutUint32(p[4:], 4) // PF_R
		binary.LittleEndian.PutUint64(p[8:], uint64(offs[i]))
		binary.LittleEndian.PutUint64(p[16:], r.addr)
		binary.LittleEndian.PutUint64(p[24:], r.addr)
		binary.LittleEndian.PutUint64(p[32:], uint64(len(r.data)))
		binary.LittleEndian.PutUint64(p[40:], uint64(len(r.data)))
		binary.LittleEndian.PutUint64(p[48:], 0x1000)
	}
	note := phdrs[len(regions)*elfPhdr64:]
	binary.LittleEndian.PutUint32(note[0:], 4) // PT_NOTE
	binary.LittleEndian.PutUint64(note[8:], uint64(dataOff))

	out := append(append([]byte(nil), ehdr...), phdrs...)
	for _, r := range regions {
		out = append(out, r.data...)
	}
	return out
}

// buildELFCore32 assembles a 32-bit little-endian ELF core with one region.
func buildELFCore32(region memRegion) []byte {
	phoff := elfEhdr32
	dataOff := phoff + elfPhdr32

	ehdr := make([]byte, elfEhdr32)
	ehdr[0], ehdr[1], ehdr[2], ehdr[3] = 0x7F, 'E', 'L', 'F'
	ehdr[4] = 1 // ELFCLASS32
	ehdr[5] = elfDataLE
	ehdr[6] = 1
	binary.LittleEndian.PutUint16(ehdr[16:], elfTypeCore)
	binary.LittleEndian.PutUint16(ehdr[18:], 3) // EM_386
	binary.LittleEndian.PutUint32(ehdr[20:], 1)
	binary.LittleEndian.PutUint32(ehdr[28:], uint32(phoff))
	binary.LittleEndian.PutUint16(ehdr[40:], elfEhdr32)
	binary.LittleEndian.PutUint16(ehdr[42:], elfPhdr32)
	binary.LittleEndian.PutUint16(ehdr[44:], 1)

	p := make([]byte, elfPhdr32)
	binary.LittleEndian.PutUint32(p[0:], elfPTLoad)
	binary.LittleEndian.PutUint32(p[4:], uint32(dataOff))
	binary.LittleEndian.PutUint32(p[8:], uint32(region.addr))
	binary.LittleEndian.PutUint32(p[12:], uint32(region.addr))
	binary.LittleEndian.PutUint32(p[16:], uint32(len(region.data)))
	binary.LittleEndian.PutUint32(p[20:], uint32(len(region.data)))

	out := append(append([]byte(nil), ehdr...), p...)
	return append(out, region.data...)
}

func TestELFCoreParseAndLocate(t *testing.T) {
	// Regions deliberately out of address order; the parser must sort them.
	regions := []memRegion{
		{0x7FFF0000, payloadFor(0x7FFF0000, 32)},
		{0x400000, payloadFor(0x400000, 64)},
	}
	c, err := Open(writeCapture(t, "core.elf", buildELFCore(regions)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Format != FormatELFCore {
		t.Fatalf("Format = %q, want elf-core", c.Format)
	}
	if !c.HasMap {
		t.Fatal("HasMap = false, want true")
	}
	if len(c.Segments) != 2 {
		t.Fatalf("segments = %+v, want 2", c.Segments)
	}
	lo, hi := c.Segments[0], c.Segments[1]
	if lo.AddrStart != 0x400000 || lo.AddrEnd != 0x400040 || lo.Length != 64 {
		t.Errorf("segment 0 = %+v", lo)
	}
	if hi.AddrStart != 0x7FFF0000 || hi.AddrEnd != 0x7FFF0020 {
		t.Errorf("segment 1 = %+v", hi)
	}

	f, err := os.Open(c.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, addr := range []int64{0x400000, 0x40003F, 0x7FFF0000, 0x7FFF001F} {
		loc, err := c.Locate(addr)
		if err != nil {
			t.Fatalf("Locate(%#x): %v", addr, err)
		}
		var b [1]byte
		if _, err := f.ReadAt(b[:], loc.Offset); err != nil {
			t.Fatalf("ReadAt(%#x -> %d): %v", addr, loc.Offset, err)
		}
		if b[0] != byte(addr) {
			t.Errorf("Locate(%#x) -> offset %d holds %#x, want %#x", addr, loc.Offset, b[0], byte(addr))
		}
	}
	if _, err := c.Locate(0x500000); err == nil || !strings.Contains(err.Error(), "not covered") {
		t.Errorf("Locate(gap) = %v, want not-covered error", err)
	}
}

func TestELFCore32(t *testing.T) {
	region := memRegion{0x8048000, payloadFor(0x8048000, 16)}
	c, err := Open(writeCapture(t, "core32.elf", buildELFCore32(region)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Format != FormatELFCore || len(c.Segments) != 1 {
		t.Fatalf("capture = %+v", c)
	}
	s := c.Segments[0]
	if s.AddrStart != 0x8048000 || s.AddrEnd != 0x8048010 || s.Length != 16 {
		t.Fatalf("segment = %+v", s)
	}
	f, err := os.Open(c.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	addr := int64(0x8048008)
	loc, err := c.Locate(addr)
	if err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := f.ReadAt(b[:], loc.Offset); err != nil {
		t.Fatal(err)
	}
	if want := byte(addr); b[0] != want {
		t.Errorf("byte at located offset = %#x, want %#x", b[0], want)
	}
}

func TestELFCoreTruncatedClamp(t *testing.T) {
	// A truncated core: the payload runs 32 bytes past the end of the file.
	full := buildELFCore([]memRegion{{0x1000, payloadFor(0x1000, 64)}})
	c, err := Open(writeCapture(t, "core-trunc.elf", full[:len(full)-32]))
	if err != nil {
		t.Fatal(err)
	}
	s := c.Segments[0]
	if s.Length != 32 || s.AddrEnd != 0x1020 {
		t.Fatalf("segment = %+v, want length clamped to 32", s)
	}
	if _, err := c.Locate(0x101F); err != nil {
		t.Errorf("Locate(last existing byte) = %v", err)
	}
	if _, err := c.Locate(0x1020); err == nil || !strings.Contains(err.Error(), "not covered") {
		t.Errorf("Locate(beyond clamp) = %v, want not-covered error", err)
	}
}

func TestELFCoreErrors(t *testing.T) {
	notCore := buildELFCore(nil)
	binary.LittleEndian.PutUint16(notCore[16:], 2) // ET_EXEC

	badClass := buildELFCore([]memRegion{{0x1000, payloadFor(0x1000, 8)}})
	badClass[4] = 9

	bigEndian := buildELFCore([]memRegion{{0x1000, payloadFor(0x1000, 8)}})
	bigEndian[5] = 2

	badPhent := buildELFCore([]memRegion{{0x1000, payloadFor(0x1000, 8)}})
	binary.LittleEndian.PutUint16(badPhent[54:], 64)

	badPhoff := buildELFCore([]memRegion{{0x1000, payloadFor(0x1000, 8)}})
	binary.LittleEndian.PutUint64(badPhoff[32:], 0x100000)

	noLoads := buildELFCore(nil) // only the PT_NOTE phdr

	onlyBSS := buildELFCore([]memRegion{{0x1000, nil}}) // PT_LOAD with no bytes

	for _, tc := range []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"not-a-core", notCore, "not a core dump"},
		{"bad-class", badClass, "invalid ELF class"},
		{"big-endian", bigEndian, "big-endian"},
		{"bad-phentsize", badPhent, "program header size"},
		{"phoff-past-eof", badPhoff, "program headers extend past end"},
		{"no-pt-load", noLoads, "no loadable memory segments"},
		{"only-bss", onlyBSS, "no loadable memory segments"},
		{"truncated-header", []byte{0x7F, 'E', 'L', 'F', 2, 1, 1}, "truncated ELF header"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Open(writeCapture(t, "bad.elf", tc.data))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

// --- Minidump builders and tests -------------------------------------------

// buildMinidump64 assembles a minidump whose Memory64ListStream holds the
// regions as one contiguous payload block after the range table.
func buildMinidump64(regions []memRegion) []byte {
	n := len(regions)
	dirRVA := mdmpHeaderSize
	listRVA := dirRVA + mdmpDirEnt
	baseRVA := listRVA + 16 + 16*n

	hdr := make([]byte, mdmpHeaderSize)
	copy(hdr, minidumpMagic)
	binary.LittleEndian.PutUint32(hdr[4:], 0xA793)
	binary.LittleEndian.PutUint32(hdr[8:], 1)
	binary.LittleEndian.PutUint32(hdr[12:], uint32(dirRVA))

	dir := make([]byte, mdmpDirEnt)
	binary.LittleEndian.PutUint32(dir[0:], mdmpStreamMemList64)
	binary.LittleEndian.PutUint32(dir[4:], uint32(16+16*n))
	binary.LittleEndian.PutUint32(dir[8:], uint32(listRVA))

	meta := make([]byte, 16)
	binary.LittleEndian.PutUint64(meta[0:], uint64(n))
	binary.LittleEndian.PutUint64(meta[8:], uint64(baseRVA))

	table := make([]byte, 16*n)
	pos := baseRVA
	for i, r := range regions {
		binary.LittleEndian.PutUint64(table[i*16:], r.addr)
		binary.LittleEndian.PutUint64(table[i*16+8:], uint64(len(r.data)))
		pos += len(r.data)
	}

	out := hdr
	out = append(out, dir...)
	out = append(out, meta...)
	out = append(out, table...)
	for _, r := range regions {
		out = append(out, r.data...)
	}
	return out
}

// buildMinidumpMemList assembles a minidump whose classic MemoryListStream
// points at one separate buffer per range.
func buildMinidumpMemList(regions []memRegion) []byte {
	n := len(regions)
	dirRVA := mdmpHeaderSize
	listRVA := dirRVA + mdmpDirEnt
	tableOff := listRVA + 4
	payloadOff := tableOff + 16*n

	hdr := make([]byte, mdmpHeaderSize)
	copy(hdr, minidumpMagic)
	binary.LittleEndian.PutUint32(hdr[4:], 0xA793)
	binary.LittleEndian.PutUint32(hdr[8:], 1)
	binary.LittleEndian.PutUint32(hdr[12:], uint32(dirRVA))

	dir := make([]byte, mdmpDirEnt)
	binary.LittleEndian.PutUint32(dir[0:], mdmpStreamMemList)
	binary.LittleEndian.PutUint32(dir[4:], uint32(4+16*n))
	binary.LittleEndian.PutUint32(dir[8:], uint32(listRVA))

	count := make([]byte, 4)
	binary.LittleEndian.PutUint32(count, uint32(n))

	table := make([]byte, 16*n)
	pos := payloadOff
	for i, r := range regions {
		binary.LittleEndian.PutUint64(table[i*16:], r.addr)
		binary.LittleEndian.PutUint32(table[i*16+8:], uint32(len(r.data)))
		binary.LittleEndian.PutUint32(table[i*16+12:], uint32(pos))
		pos += len(r.data)
	}

	out := hdr
	out = append(out, dir...)
	out = append(out, count...)
	out = append(out, table...)
	for _, r := range regions {
		out = append(out, r.data...)
	}
	return out
}

// buildMinidumpHeaderOnly assembles a minidump with one non-memory stream.
func buildMinidumpHeaderOnly() []byte {
	hdr := make([]byte, mdmpHeaderSize)
	copy(hdr, minidumpMagic)
	binary.LittleEndian.PutUint32(hdr[4:], 0xA793)
	binary.LittleEndian.PutUint32(hdr[8:], 1)
	binary.LittleEndian.PutUint32(hdr[12:], mdmpHeaderSize)
	dir := make([]byte, mdmpDirEnt)
	binary.LittleEndian.PutUint32(dir[0:], 3) // SystemInfoStream
	binary.LittleEndian.PutUint32(dir[4:], 0)
	binary.LittleEndian.PutUint32(dir[8:], mdmpHeaderSize+mdmpDirEnt)
	return append(hdr, dir...)
}

func TestMinidumpParseAndLocate(t *testing.T) {
	regions := []memRegion{
		{0x10000, payloadFor(0x10000, 48)},
		{0x7FF000, payloadFor(0x7FF000, 16)},
	}
	c, err := Open(writeCapture(t, "crash.dmp", buildMinidump64(regions)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Format != FormatMinidump {
		t.Fatalf("Format = %q, want minidump", c.Format)
	}
	if !c.HasMap || len(c.Segments) != 2 {
		t.Fatalf("capture = %+v", c)
	}
	lo, hi := c.Segments[0], c.Segments[1]
	if lo.AddrStart != 0x10000 || lo.AddrEnd != 0x10030 || lo.Length != 48 {
		t.Errorf("segment 0 = %+v", lo)
	}
	if hi.AddrStart != 0x7FF000 || hi.AddrEnd != 0x7FF010 {
		t.Errorf("segment 1 = %+v", hi)
	}

	f, err := os.Open(c.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, addr := range []int64{0x10000, 0x1002F, 0x7FF000, 0x7FF00F} {
		loc, err := c.Locate(addr)
		if err != nil {
			t.Fatalf("Locate(%#x): %v", addr, err)
		}
		var b [1]byte
		if _, err := f.ReadAt(b[:], loc.Offset); err != nil {
			t.Fatalf("ReadAt(%#x -> %d): %v", addr, loc.Offset, err)
		}
		if b[0] != byte(addr) {
			t.Errorf("Locate(%#x) -> offset %d holds %#x, want %#x", addr, loc.Offset, b[0], byte(addr))
		}
	}
}

func TestMinidumpMemoryListFallback(t *testing.T) {
	regions := []memRegion{
		{0x2000, payloadFor(0x2000, 24)},
		{0x9000, payloadFor(0x9000, 8)},
	}
	c, err := Open(writeCapture(t, "old.dmp", buildMinidumpMemList(regions)))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Segments) != 2 {
		t.Fatalf("segments = %+v, want 2", c.Segments)
	}
	f, err := os.Open(c.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, addr := range []int64{0x2000, 0x2017, 0x9000, 0x9007} {
		loc, err := c.Locate(addr)
		if err != nil {
			t.Fatalf("Locate(%#x): %v", addr, err)
		}
		var b [1]byte
		if _, err := f.ReadAt(b[:], loc.Offset); err != nil {
			t.Fatalf("ReadAt(%#x -> %d): %v", addr, loc.Offset, err)
		}
		if b[0] != byte(addr) {
			t.Errorf("Locate(%#x) -> offset %d holds %#x, want %#x", addr, loc.Offset, b[0], byte(addr))
		}
	}
}

func TestMinidumpTruncatedClamp(t *testing.T) {
	full := buildMinidump64([]memRegion{{0x1000, payloadFor(0x1000, 64)}})
	c, err := Open(writeCapture(t, "trunc.dmp", full[:len(full)-40]))
	if err != nil {
		t.Fatal(err)
	}
	s := c.Segments[0]
	if s.Length != 24 || s.AddrEnd != 0x1018 {
		t.Fatalf("segment = %+v, want length clamped to 24", s)
	}
}

func TestMinidumpErrors(t *testing.T) {
	noStreams := make([]byte, mdmpHeaderSize)
	copy(noStreams, minidumpMagic)

	bigDir := make([]byte, mdmpHeaderSize)
	copy(bigDir, minidumpMagic)
	binary.LittleEndian.PutUint32(bigDir[8:], 1)
	binary.LittleEndian.PutUint32(bigDir[12:], mdmpHeaderSize) // dir claims bytes past EOF

	hugeTable := buildMinidump64([]memRegion{{0x1000, payloadFor(0x1000, 8)}})
	// Inflate the range count so the table no longer fits in the file.
	binary.LittleEndian.PutUint64(hugeTable[mdmpHeaderSize+mdmpDirEnt:], 1000)

	streamPastEOF := buildMinidump64([]memRegion{{0x1000, payloadFor(0x1000, 8)}})
	binary.LittleEndian.PutUint32(streamPastEOF[mdmpHeaderSize+4:], 0xFFFFFF00)

	for _, tc := range []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"no-streams", noStreams, "no streams"},
		{"dir-past-eof", bigDir, "directory extends past end"},
		{"huge-table", hugeTable, "truncated minidump Memory64List table"},
		{"stream-past-eof", streamPastEOF, "extends past end of file"},
		{"no-memory-streams", buildMinidumpHeaderOnly(), "no memory streams"},
		{"truncated-header", []byte("MDMP\x01\x00"), "truncated minidump header"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Open(writeCapture(t, "bad.dmp", tc.data))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestNotYetSupported(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"pagedu64", append([]byte("PAGEDU64"), make([]byte, 64)...), "not yet supported"},
		{"pagedump", append([]byte("PAGEDUMP"), make([]byte, 64)...), "not yet supported"},
		{"avml", append([]byte("AVML\x01\x00\x00\x00"), make([]byte, 64)...), "not yet supported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Open(writeCapture(t, "dump.bin", tc.data))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
