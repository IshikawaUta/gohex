package service

import (
	"encoding/binary"
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
	if _, err := app.MemoryInfo(writeFile(t, "kernel.dmp", append([]byte("PAGEDU64"), make([]byte, 64)...))); err == nil || !strings.Contains(err.Error(), "not yet supported") {
		t.Errorf("MemoryInfo(PAGEDU64) = %v, want not-yet-supported error", err)
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
