package service

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildLime writes a single-range LiME capture whose payload byte at
// position i is byte(start+i).
func buildLime(start, end uint64) []byte { // end inclusive
	h := make([]byte, 32)
	copy(h, "EMiL")
	binary.LittleEndian.PutUint32(h[4:], 1)
	binary.LittleEndian.PutUint64(h[8:], start)
	binary.LittleEndian.PutUint64(h[16:], end)
	out := append([]byte(nil), h...)
	for a := start; a <= end; a++ {
		out = append(out, byte(a))
		if a == end {
			break
		}
	}
	return out
}

func TestMemoryInfoAndLocate(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "ram.lime", buildLime(0x1000, 0x10FF))

	mc, err := app.MemoryInfo(p)
	if err != nil {
		t.Fatal(err)
	}
	if mc.Format != "lime" || !mc.HasMap || mc.Size != int64(len(buildLime(0x1000, 0x10FF))) {
		t.Fatalf("capture = %+v", mc)
	}
	if len(mc.Segments) != 1 {
		t.Fatalf("segments = %+v", mc.Segments)
	}
	s := mc.Segments[0]
	if s.Offset != 32 || s.Length != 0x100 || s.AddrStart != 0x1000 || s.AddrEnd != 0x1100 {
		t.Fatalf("segment = %+v", s)
	}

	logged := caseAudit(t, app)
	for _, want := range []string{`"op":"memory"`, `"format":"lime"`, "read-only"} {
		if !strings.Contains(logged, want) {
			t.Errorf("audit log missing %s:\n%s", want, logged)
		}
	}

	loc, err := app.MemoryLocate(p, 0x1007)
	if err != nil {
		t.Fatal(err)
	}
	if loc.Offset != 32+7 || loc.Segment != 0 {
		t.Fatalf("Locate(0x1007) = %+v", loc)
	}
	if _, err := app.MemoryLocate(p, 0x5000); err == nil || !strings.Contains(err.Error(), "not covered") {
		t.Errorf("Locate(uncovered) = %v, want not-covered error", err)
	}
}

func TestMemoryErrors(t *testing.T) {
	app := newTestApp(t)

	if _, err := app.MemoryInfo(""); err == nil || !strings.Contains(err.Error(), "empty path") {
		t.Errorf("MemoryInfo(\"\") = %v, want empty-path error", err)
	}
	if _, err := app.MemoryInfo(filepath.Join(t.TempDir(), "missing.lime")); err == nil || !strings.Contains(err.Error(), "memory:") {
		t.Errorf("MemoryInfo(missing) = %v, want memory-prefixed error", err)
	}
	if _, err := app.MemoryInfo(writeFile(t, "kernel.dmp", append([]byte("PAGEDU64"), make([]byte, 64)...))); err == nil || !strings.Contains(err.Error(), "truncated Windows dump header") {
		t.Errorf("MemoryInfo(PAGEDU64) = %v, want truncated-header error", err)
	}
	if _, err := app.MemoryInfo(writeFile(t, "old.dmp", append([]byte("PAGEDUMP"), make([]byte, 64)...))); err == nil || !strings.Contains(err.Error(), "not yet supported") {
		t.Errorf("MemoryInfo(PAGEDUMP) = %v, want not-yet-supported error", err)
	}

	raw := writeFile(t, "ram.raw", []byte("not a structured capture"))
	mc, err := app.MemoryInfo(raw)
	if err != nil {
		t.Fatal(err)
	}
	if mc.Format != "raw" || mc.HasMap {
		t.Fatalf("capture = %+v, want raw without address map", mc)
	}
	if _, err := app.MemoryLocate(raw, 0); err == nil || !strings.Contains(err.Error(), "no address map") {
		t.Errorf("MemoryLocate(raw) = %v, want no-map error", err)
	}
	if _, err := app.MemoryLocate("", 0); err == nil || !strings.Contains(err.Error(), "empty path") {
		t.Errorf("MemoryLocate(\"\") = %v, want empty-path error", err)
	}
}

// TestMemoryELFCore runs a minimal 64-bit ELF core through the service: one
// PT_LOAD whose payload byte at position i is byte(0x400000+i).
func TestMemoryELFCore(t *testing.T) {
	const (
		ehdrLen = 64
		phdrLen = 56
		segLen  = 32
	)
	data := make([]byte, ehdrLen+phdrLen+segLen)
	copy(data, []byte{0x7F, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:], 4)       // ET_CORE
	binary.LittleEndian.PutUint32(data[20:], 1)       // version
	binary.LittleEndian.PutUint64(data[32:], ehdrLen) // phoff
	binary.LittleEndian.PutUint16(data[52:], ehdrLen) // ehsize
	binary.LittleEndian.PutUint16(data[54:], phdrLen) // phentsize
	binary.LittleEndian.PutUint16(data[56:], 1)       // phnum
	ph := data[ehdrLen:]
	binary.LittleEndian.PutUint32(ph[0:], 1)               // PT_LOAD
	binary.LittleEndian.PutUint64(ph[8:], ehdrLen+phdrLen) // offset
	binary.LittleEndian.PutUint64(ph[16:], 0x400000)       // vaddr
	binary.LittleEndian.PutUint64(ph[32:], segLen)         // filesz
	binary.LittleEndian.PutUint64(ph[40:], segLen)         // memsz
	for i := 0; i < segLen; i++ {
		data[ehdrLen+phdrLen+i] = byte(0x400000 + i)
	}

	app := newTestApp(t)
	p := writeFile(t, "core.elf", data)
	mc, err := app.MemoryInfo(p)
	if err != nil {
		t.Fatal(err)
	}
	if mc.Format != "elf-core" || !mc.HasMap || len(mc.Segments) != 1 {
		t.Fatalf("capture = %+v", mc)
	}
	if logged := caseAudit(t, app); !strings.Contains(logged, `"format":"elf-core"`) {
		t.Errorf("audit log missing elf-core format:\n%s", logged)
	}
	loc, err := app.MemoryLocate(p, 0x400010)
	if err != nil {
		t.Fatal(err)
	}
	if loc.Offset != ehdrLen+phdrLen+0x10 || loc.Segment != 0 {
		t.Fatalf("Locate(0x400010) = %+v", loc)
	}
}

func TestMemoryOpenLIME(t *testing.T) {
	app := newTestApp(t)
	payload := make([]byte, 0x100)
	for i := range payload {
		payload[i] = byte(0x1000 + i)
	}
	p := writeFile(t, "ram.lime", buildLime(0x1000, 0x10FF))

	doc, err := app.MemoryOpen(p, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Size != 0x100 {
		t.Fatalf("doc size = %d, want 256", doc.Size)
	}
	wd, err := app.ReadWindow(doc.ID, 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wd.Bytes, payload[:16]) {
		t.Fatalf("window = %x, want %x", wd.Bytes, payload[:16])
	}
	logged := caseAudit(t, app)
	for _, want := range []string{`"op":"memory-view"`, `"format":"lime"`, "read-only"} {
		if !strings.Contains(logged, want) {
			t.Errorf("audit log missing %s:\n%s", want, logged)
		}
	}

	// A sub-range becomes its own document over the same capture.
	sub, err := app.MemoryOpen(p, 4, 8)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Size != 8 {
		t.Fatalf("sub size = %d, want 8", sub.Size)
	}
	wd, err = app.ReadWindow(sub.ID, 0, 8)
	if err != nil || !bytes.Equal(wd.Bytes, payload[4:12]) {
		t.Fatalf("sub window = %x, err %v", wd.Bytes, err)
	}
	// A size past the end is clamped.
	clamped, err := app.MemoryOpen(p, 0, 1<<20)
	if err != nil || clamped.Size != 0x100 {
		t.Fatalf("clamped = %+v, err %v", clamped, err)
	}
}

func TestMemoryOpenAVML(t *testing.T) {
	app := newTestApp(t)
	payload := make([]byte, 0x80)
	for i := range payload {
		payload[i] = byte(0x2000 + i)
	}
	p := writeFile(t, "ram.avml", buildAVMLCapture(0x2000, payload))

	doc, err := app.MemoryOpen(p, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Size != 0x80 {
		t.Fatalf("doc size = %d, want 128", doc.Size)
	}
	wd, err := app.ReadWindow(doc.ID, 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wd.Bytes, payload[:16]) {
		t.Fatalf("window = %x, want %x", wd.Bytes, payload[:16])
	}
	if logged := caseAudit(t, app); !strings.Contains(logged, `"format":"avml"`) {
		t.Errorf("audit log missing avml format:\n%s", logged)
	}
	// The metadata view agrees the capture is compressed.
	mc, err := app.MemoryInfo(p)
	if err != nil || !mc.Compressed {
		t.Fatalf("capture = %+v, err %v", mc, err)
	}
}

func TestMemoryOpenErrors(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.MemoryOpen(filepath.Join(t.TempDir(), "missing.lime"), 0, 0); err == nil {
		t.Error("MemoryOpen(missing) = nil, want error")
	}
	p := writeFile(t, "ram.lime", buildLime(0x1000, 0x10FF))
	if _, err := app.MemoryOpen(p, -1, 0); err == nil {
		t.Error("MemoryOpen(-1) = nil, want error")
	}
	if _, err := app.MemoryOpen(p, 1<<30, 0); err == nil {
		t.Error("MemoryOpen(past end) = nil, want error")
	}
}

// buildAVMLCapture wraps one AVML v2 block around payload, stored as a
// Snappy framed uncompressed chunk (no real compressor needed in tests).
func buildAVMLCapture(start uint64, payload []byte) []byte {
	h := make([]byte, 32)
	copy(h, "AVML")
	binary.LittleEndian.PutUint32(h[4:], 2)
	binary.LittleEndian.PutUint64(h[8:], start)
	binary.LittleEndian.PutUint64(h[16:], start+uint64(len(payload))-1)

	id := []byte{0xff, 0x06, 0x00, 0x00, 's', 'N', 'a', 'P', 'p', 'Y'}
	ln := len(payload) + 4
	frame := []byte{0x01, byte(ln), byte(ln >> 8), byte(ln >> 16)}
	crc := crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli))
	frame = binary.LittleEndian.AppendUint32(frame, ((crc>>15)|(crc<<17))+0xa282ead8)
	frame = append(frame, payload...)

	stream := append(id, frame...)
	var trailer [8]byte
	binary.LittleEndian.PutUint64(trailer[:], uint64(len(stream)))
	out := append(h, stream...)
	return append(out, trailer[:]...)
}

// buildCoreWithThread assembles a minimal 64-bit ELF core with an
// NT_PRSTATUS note (thread 7, rip/rsp/rbp) and a PT_LOAD stack carrying
// a two-frame pointer chain.
func buildCoreWithThread() []byte {
	const stackVA = uint64(0x7FFE0000)
	const stackSize = 0x1000
	const regsOff = 232
	const pidOff = 152

	prstatus := make([]byte, regsOff+27*8)
	binary.LittleEndian.PutUint32(prstatus[pidOff:], 7)
	regs := prstatus[regsOff:]
	binary.LittleEndian.PutUint64(regs[10*8:], stackVA+0x100) // rbp
	binary.LittleEndian.PutUint64(regs[15*8:], stackVA+0x40)  // rsp
	binary.LittleEndian.PutUint64(regs[16*8:], 0x402000)      // rip

	// Note: namesz, descsz, type, name "CORE\0" padded, desc padded.
	nb := []byte("CORE\x00")
	note := make([]byte, 12+len(nb)+len(prstatus)+8)
	binary.LittleEndian.PutUint32(note[0:4], uint32(len(nb)))
	binary.LittleEndian.PutUint32(note[4:8], uint32(len(prstatus)))
	binary.LittleEndian.PutUint32(note[8:12], 1) // NT_PRSTATUS
	copy(note[12:], nb)
	descOff := (12 + len(nb) + 3) &^ 3
	copy(note[descOff:], prstatus)
	noteLen := (descOff + len(prstatus) + 3) &^ 3

	stack := make([]byte, stackSize)
	binary.LittleEndian.PutUint64(stack[0x100:], stackVA+0x180)
	binary.LittleEndian.PutUint64(stack[0x108:], 0x401010)
	binary.LittleEndian.PutUint64(stack[0x180:], 0)
	binary.LittleEndian.PutUint64(stack[0x188:], 0x401020)

	const ehdrLen = 64
	const phnum = 2
	const phoff = ehdrLen
	notesOff := phoff + phnum*56
	stackOff := notesOff + noteLen

	out := make([]byte, stackOff+stackSize)
	copy(out, []byte{0x7F, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(out[16:18], 4)     // ET_CORE
	binary.LittleEndian.PutUint32(out[20:24], 0x3E)  // EM_X86_64
	binary.LittleEndian.PutUint64(out[32:40], phoff) // e_phoff
	binary.LittleEndian.PutUint16(out[52:54], ehdrLen)
	binary.LittleEndian.PutUint16(out[54:56], 56)
	binary.LittleEndian.PutUint16(out[56:58], phnum)
	putPhdr := func(i int, typ uint32, off, vaddr, filesz uint64) {
		p := out[phoff+i*56:]
		binary.LittleEndian.PutUint32(p[0:4], typ)
		binary.LittleEndian.PutUint64(p[8:16], off)
		binary.LittleEndian.PutUint64(p[16:24], vaddr)
		binary.LittleEndian.PutUint64(p[32:40], filesz)
	}
	putPhdr(0, 4, uint64(notesOff), 0, uint64(noteLen)) // PT_NOTE
	putPhdr(1, 1, uint64(stackOff), stackVA, stackSize) // PT_LOAD
	copy(out[notesOff:], note)
	copy(out[stackOff:], stack)
	return out
}

func TestMemoryStackWalk(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "core", buildCoreWithThread())

	frames, err := app.MemoryStack(p, 7)
	if err != nil {
		t.Fatalf("MemoryStack: %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("frames = %+v", frames)
	}
	if frames[0].Addr != 0x402000 || frames[1].Addr != 0x401010 || frames[2].Addr != 0x401020 {
		t.Fatalf("frame addrs = %#x %#x %#x", frames[0].Addr, frames[1].Addr, frames[2].Addr)
	}
	if !strings.Contains(caseAudit(t, app), `"op":"stack-walk"`) {
		t.Error("audit log missing stack-walk record")
	}
	if _, err := app.MemoryStack(p, 99); err == nil {
		t.Fatal("unknown thread should fail")
	}
	if _, err := app.MemoryStack("", 1); err == nil {
		t.Fatal("empty path should fail")
	}
}

func TestMemoryStackNoDetails(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "ram.lime", buildLime(0x1000, 0x10FF))
	if _, err := app.MemoryStack(p, 1); err == nil {
		t.Fatal("LiME capture has no thread details")
	}
}

func TestMemoryCompareModulesEmpty(t *testing.T) {
	app := newTestApp(t)
	p1 := writeFile(t, "a.lime", buildLime(0x1000, 0x10FF))
	p2 := writeFile(t, "b.lime", buildLime(0x2000, 0x20FF))
	diff, err := app.MemoryCompareModules(p1, p2)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Common != 0 || len(diff.OnlyA) != 0 || len(diff.OnlyB) != 0 {
		t.Fatalf("diff = %+v", diff)
	}
	if _, err := app.MemoryCompareModules("", p2); err == nil {
		t.Fatal("empty path should fail")
	}
}

func TestMemoryDumpRange(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "ram.lime", buildLime(0x1000, 0x10FF))
	out := filepath.Join(t.TempDir(), "slice.bin")

	n, err := app.MemoryDumpRange(p, 0x1007, 16, out)
	if err != nil {
		t.Fatalf("MemoryDumpRange: %v", err)
	}
	if n != 16 {
		t.Fatalf("written = %d", n)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range got {
		if b != byte(0x1007+i) {
			t.Fatalf("byte %d = %#x", i, b)
		}
	}
	if !strings.Contains(caseAudit(t, app), `"op":"memory-extract"`) {
		t.Error("audit log missing memory-extract record")
	}
}

func TestMemoryDumpRangeErrors(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "ram.lime", buildLime(0x1000, 0x10FF))
	out := filepath.Join(t.TempDir(), "x.bin")
	if _, err := app.MemoryDumpRange(p, 0x1000, 0, out); err == nil {
		t.Fatal("zero length should fail")
	}
	if _, err := app.MemoryDumpRange(p, 0x1000, maxDumpRange+1, out); err == nil {
		t.Fatal("oversized length should fail")
	}
	if _, err := app.MemoryDumpRange(p, 0x9999, 16, out); err == nil {
		t.Fatal("uncovered address should fail")
	}
	if _, err := app.MemoryDumpRange("", 0x1000, 16, out); err == nil {
		t.Fatal("empty path should fail")
	}
	if _, err := app.MemoryDumpRange(p, 0x1000, 16, ""); err == nil {
		t.Fatal("empty output should fail")
	}
}
