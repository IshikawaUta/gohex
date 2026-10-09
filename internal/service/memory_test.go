package service

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
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
