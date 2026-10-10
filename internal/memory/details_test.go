package memory

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

// --- minidump with details -------------------------------------------------

// buildMdmpWithDetails assembles a minidump carrying SystemInfo (AMD64),
// a two-entry ModuleList, a one-entry ThreadList with an AMD64 CONTEXT
// and a stack range in the Memory64List, and an ACCESS_VIOLATION
// ExceptionStream.
func buildMdmpWithDetails() []byte {
	const stackVA = uint64(0x7FFD0000)
	const stackSize = 0x1000
	const stackFileOff = 0 // filled later; payload is appended last

	// Stream bodies.
	sysInfo := make([]byte, mdmpSysInfoMin)
	binary.LittleEndian.PutUint16(sysInfo[0:2], mdmpArchAMD64)

	// ModuleList: two modules with MINIDUMP_STRING names.
	const nMods = 2
	modList := make([]byte, 4+nMods*mdmpModuleEnt)
	binary.LittleEndian.PutUint32(modList[0:4], nMods)
	// Names are appended after the table; RVAs are fixed up below.
	name0 := mdmpUTF16("app.exe")
	name1 := mdmpUTF16("ntdll.dll")
	const modTabRVA = 0 // fixed up by caller layout; we build everything
	// relative offsets inside the stream blob: table then strings.
	nameOff0 := len(modList)
	nameOff1 := nameOff0 + len(name0)
	// ModuleNameRva is absolute; caller sets stream base. We stash the
	// in-stream offset in a wrapper the layout code relocates.
	putModule := func(p []byte, base uint64, size uint64, nameOff int) {
		binary.LittleEndian.PutUint64(p[0:8], base)
		binary.LittleEndian.PutUint32(p[8:12], uint32(size))
		// ModuleNameRva at [20:24] fixed up after we know stream RVA.
		_ = nameOff
	}
	putModule(modList[4:4+mdmpModuleEnt], 0x401000, 0x2000, nameOff0)
	putModule(modList[4+mdmpModuleEnt:], 0x7FF80000, 0x1F000, nameOff1)
	modList = append(modList, name0...)
	modList = append(modList, name1...)

	// ThreadList with CONTEXT and stack descriptor.
	const nThr = 1
	thrList := make([]byte, 4+nThr*mdmpThreadEnt)
	binary.LittleEndian.PutUint32(thrList[0:4], nThr)
	thr := thrList[4:]
	binary.LittleEndian.PutUint32(thr[0:4], 42) // ThreadId
	binary.LittleEndian.PutUint64(thr[16:24], 0x7FFE0000)
	binary.LittleEndian.PutUint64(thr[24:32], stackVA) // stack start
	binary.LittleEndian.PutUint32(thr[32:36], stackSize)
	// Stack payload RVA + context RVA fixed up after layout.

	// CONTEXT: rip/rsp/rbp per winnt.h offsets.
	ctx := make([]byte, contextAmd64Size)
	binary.LittleEndian.PutUint64(ctx[ctxAmd64Rax:], 0x1111)
	binary.LittleEndian.PutUint64(ctx[ctxAmd64Rsp:], stackVA+0x80)
	binary.LittleEndian.PutUint64(ctx[ctxAmd64Rbp:], stackVA+0x100)
	binary.LittleEndian.PutUint64(ctx[ctxAmd64Rip:], 0x402000)

	// ExceptionStream.
	exc := make([]byte, mdmpExceptionSt)
	binary.LittleEndian.PutUint32(exc[0:4], 42)
	binary.LittleEndian.PutUint32(exc[8:12], 0xC0000005)
	binary.LittleEndian.PutUint64(exc[24:32], 0x401000) // ExceptionAddress
	binary.LittleEndian.PutUint32(exc[40:44], 2)        // NumberParameters
	binary.LittleEndian.PutUint64(exc[48:56], 0)        // read
	binary.LittleEndian.PutUint64(exc[56:64], 0x401000) // fault address

	// Stack payload: frame-pointer chain.
	stack := make([]byte, stackSize)
	// [stackVA+0x100] = {saved rbp = stackVA+0x180, ret = 0x401010}
	binary.LittleEndian.PutUint64(stack[0x100:], stackVA+0x180)
	binary.LittleEndian.PutUint64(stack[0x108:], 0x401010)
	// [stackVA+0x180] = {0, ret = 0x401020}
	binary.LittleEndian.PutUint64(stack[0x180:], 0)
	binary.LittleEndian.PutUint64(stack[0x188:], 0x401020)

	// Memory64List: one range covering the stack.
	// MINIDUMP_MEMORY64_LIST: NumberOfMemoryRanges u64, BaseRva u64,
	// then (StartOfMemoryRange u64, DataSize u64) per range.
	const mem64Hdr = 16
	const mem64Ent = 16
	memList := make([]byte, mem64Hdr+mem64Ent)
	binary.LittleEndian.PutUint64(memList[0:8], 1)
	binary.LittleEndian.PutUint64(memList[8:16], 0) // BaseRva fixed up
	binary.LittleEndian.PutUint64(memList[16:24], stackVA)
	binary.LittleEndian.PutUint64(memList[24:32], stackSize)
	_ = stackFileOff
	_ = modTabRVA

	// Layout: header, directory, streams, payload.
	const nStreams = 5
	const dirRVA uint32 = mdmpHeaderSize
	const streamBase uint32 = dirRVA + nStreams*mdmpDirEnt

	sysRVA := streamBase
	thrRVA := sysRVA + uint32(len(sysInfo))
	modRVA := thrRVA + uint32(len(thrList))
	excRVA := modRVA + uint32(len(modList))
	memRVA := excRVA + uint32(len(exc))
	payloadRVA := memRVA + uint32(len(memList))

	// Fix up RVAs inside streams.
	binary.LittleEndian.PutUint32(modList[4+20:4+24], modRVA+uint32(nameOff0)) // name0 RVA
	binary.LittleEndian.PutUint32(modList[4+mdmpModuleEnt+20:4+mdmpModuleEnt+24], modRVA+uint32(nameOff1))
	_ = nameOff0
	// Stack Memory LOCATION: size at [32:36] already set; RVA at [36:40].
	binary.LittleEndian.PutUint32(thr[36:40], payloadRVA)
	// ThreadContext LOCATION at [40:48].
	binary.LittleEndian.PutUint32(thr[40:44], contextAmd64Size)
	binary.LittleEndian.PutUint32(thr[44:48], payloadRVA+stackSize)
	binary.LittleEndian.PutUint64(memList[8:16], uint64(payloadRVA)) // BaseRva

	// Assemble.
	var buf bytes.Buffer
	hdr := make([]byte, mdmpHeaderSize)
	copy(hdr[0:4], minidumpMagic)
	binary.LittleEndian.PutUint32(hdr[4:8], 0xA793)
	binary.LittleEndian.PutUint32(hdr[8:12], nStreams)
	binary.LittleEndian.PutUint32(hdr[12:16], dirRVA)
	buf.Write(hdr)
	writeEnt := func(typ, size, rva uint32) {
		var e [mdmpDirEnt]byte
		binary.LittleEndian.PutUint32(e[0:4], typ)
		binary.LittleEndian.PutUint32(e[4:8], size)
		binary.LittleEndian.PutUint32(e[8:12], rva)
		buf.Write(e[:])
	}
	writeEnt(mdmpStreamSystemInfo, uint32(len(sysInfo)), sysRVA)
	writeEnt(mdmpStreamThreadList, uint32(len(thrList)), thrRVA)
	writeEnt(mdmpStreamModuleList, uint32(len(modList)), modRVA)
	writeEnt(mdmpStreamException, uint32(len(exc)), excRVA)
	writeEnt(mdmpStreamMemList64, uint32(len(memList)), memRVA)
	buf.Write(sysInfo)
	buf.Write(thrList)
	buf.Write(modList)
	buf.Write(exc)
	buf.Write(memList)
	buf.Write(stack)
	buf.Write(ctx)
	return buf.Bytes()
}

func mdmpUTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 4+len(u)*2)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(u)*2))
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[4+i*2:], c)
	}
	return out
}

func TestOpenMinidumpDetails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crash.dmp")
	if err := os.WriteFile(path, buildMdmpWithDetails(), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if c.Format != FormatMinidump {
		t.Fatalf("Format = %q", c.Format)
	}
	d := c.Details
	if d == nil {
		t.Fatal("Details = nil")
	}
	if d.Arch != "x86-64" || d.OS != "windows" {
		t.Fatalf("arch/os = %q/%q", d.Arch, d.OS)
	}
	if len(d.Modules) != 2 {
		t.Fatalf("modules = %d", len(d.Modules))
	}
	if d.Modules[0].Name != "app.exe" || d.Modules[0].Base != 0x401000 || d.Modules[0].Size != 0x2000 {
		t.Fatalf("module[0] = %+v", d.Modules[0])
	}
	if d.Modules[1].Name != "ntdll.dll" {
		t.Fatalf("module[1] = %+v", d.Modules[1])
	}
	if len(d.Threads) != 1 {
		t.Fatalf("threads = %d", len(d.Threads))
	}
	th := d.Threads[0]
	if th.ID != 42 || th.StackStart != 0x7FFD0000 || th.StackEnd != 0x7FFD1000 {
		t.Fatalf("thread = %+v", th)
	}
	if th.Registers["rip"] != 0x402000 || th.Registers["rsp"] != 0x7FFD0080 || th.Registers["rbp"] != 0x7FFD0100 {
		t.Fatalf("registers = %v", th.Registers)
	}
	if th.Registers["rax"] != 0x1111 {
		t.Fatalf("rax = %#x", th.Registers["rax"])
	}
	if d.Exception == nil {
		t.Fatal("exception = nil")
	}
	if d.Exception.Code != 0xC0000005 || d.Exception.ThreadID != 42 || d.Exception.Address != 0x401000 {
		t.Fatalf("exception = %+v", d.Exception)
	}
	if d.Exception.Desc != "ACCESS_VIOLATION" {
		t.Fatalf("exception desc = %q", d.Exception.Desc)
	}
}

func TestWalkStackMinidump(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crash.dmp")
	if err := os.WriteFile(path, buildMdmpWithDetails(), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	frames, err := c.WalkStack(path, 42)
	if err != nil {
		t.Fatalf("WalkStack: %v", err)
	}
	// Expect rip + two return addresses, all inside the app.exe module.
	if len(frames) != 3 {
		t.Fatalf("frames = %d, want 3: %+v", len(frames), frames)
	}
	if frames[0].Addr != 0x402000 || frames[1].Addr != 0x401010 || frames[2].Addr != 0x401020 {
		t.Fatalf("frame addrs = %#x %#x %#x", frames[0].Addr, frames[1].Addr, frames[2].Addr)
	}
	for i, f := range frames {
		if f.Module != "app.exe" {
			t.Fatalf("frame[%d] module = %q", i, f.Module)
		}
	}
	if frames[1].Offset != 0x10 { // 0x401010 - 0x401000
		t.Fatalf("frame[1] offset = %#x", frames[1].Offset)
	}
}

func TestWalkStackUnknownThread(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crash.dmp")
	if err := os.WriteFile(path, buildMdmpWithDetails(), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WalkStack(path, 99); err == nil {
		t.Fatal("unknown thread should fail")
	}
}

// --- ELF core with notes ---------------------------------------------------

// buildELFCoreNotes assembles a 64-bit ELF core with a PT_NOTE holding
// NT_PRPSINFO, one NT_PRSTATUS and NT_FILE, plus a PT_LOAD stack segment.
func buildELFCoreNotes() []byte {
	const stackVA = uint64(0x7FFE0000)
	const stackSize = 0x1000

	// Note bodies.
	prps := make([]byte, 136)
	copy(prps[elfPRPSNameOff:], "gohexcore")

	prstatus := make([]byte, elf64PRStatusOff+27*8)
	binary.LittleEndian.PutUint32(prstatus[elf64PRPidOff:], 77)
	regs := prstatus[elf64PRStatusOff:]
	// gregset: rbp = idx 10, rsp = idx 15, rip = idx 16.
	binary.LittleEndian.PutUint64(regs[10*8:], stackVA+0x100)
	binary.LittleEndian.PutUint64(regs[15*8:], stackVA+0x40)
	binary.LittleEndian.PutUint64(regs[16*8:], 0x402000)
	binary.LittleEndian.PutUint64(regs[0:], 0xAA) // r8 marker

	// NT_FILE: two mappings, names after the table.
	nfCount := uint64(2)
	nfTable := make([]byte, 16+2*24)
	binary.LittleEndian.PutUint64(nfTable[0:8], nfCount)
	binary.LittleEndian.PutUint64(nfTable[8:16], 0x1000)
	// entry0: /usr/bin/app [0x400000,0x403000) ofs 0
	binary.LittleEndian.PutUint64(nfTable[16:24], 0x400000)
	binary.LittleEndian.PutUint64(nfTable[24:32], 0x403000)
	binary.LittleEndian.PutUint64(nfTable[32:40], 0)
	// entry1: /lib/libc.so.6 [0x7F000000,0x7F020000) ofs 0
	binary.LittleEndian.PutUint64(nfTable[40:48], 0x7F000000)
	binary.LittleEndian.PutUint64(nfTable[48:56], 0x7F020000)
	binary.LittleEndian.PutUint64(nfTable[56:64], 0)
	nfNames := append([]byte("/usr/bin/app\x00"), "/lib/libc.so.6\x00"...)
	nfDesc := append(nfTable, nfNames...)

	// Assemble note blob: name "CORE" + NUL.
	notes := appendNote(nil, "CORE", elfNotePRPSInfo, prps)
	notes = appendNote(notes, "CORE", elfNotePRStatus, prstatus)
	notes = appendNote(notes, "CORE", elfNoteFile, nfDesc)

	// Stack payload.
	stack := make([]byte, stackSize)
	binary.LittleEndian.PutUint64(stack[0x100:], stackVA+0x180)
	binary.LittleEndian.PutUint64(stack[0x108:], 0x401010)
	binary.LittleEndian.PutUint64(stack[0x180:], 0)
	binary.LittleEndian.PutUint64(stack[0x188:], 0x401020)

	// ELF header + 2 program headers + notes + stack.
	const ehdrLen = elfEhdr64
	const phnum = 2
	const phoff = ehdrLen
	notesOff := phoff + phnum*elfPhdr64
	stackOff := notesOff + len(notes)

	out := make([]byte, stackOff+stackSize)
	copy(out, []byte{0x7F, 'E', 'L', 'F'})
	out[4] = elfClass64
	out[5] = elfDataLE
	out[6] = 1
	binary.LittleEndian.PutUint16(out[16:18], elfTypeCore)
	binary.LittleEndian.PutUint32(out[20:24], 0xFEEDFACE) // e_machine amd64-ish placeholder
	binary.LittleEndian.PutUint64(out[32:40], phoff)
	binary.LittleEndian.PutUint16(out[52:54], ehdrLen)
	binary.LittleEndian.PutUint16(out[54:56], elfPhdr64)
	binary.LittleEndian.PutUint16(out[56:58], phnum)

	putPhdr := func(i int, typ uint32, off uint64, vaddr uint64, filesz uint64) {
		p := out[phoff+i*elfPhdr64:]
		binary.LittleEndian.PutUint32(p[0:4], typ)
		binary.LittleEndian.PutUint64(p[8:16], off)
		binary.LittleEndian.PutUint64(p[16:24], vaddr)
		binary.LittleEndian.PutUint64(p[32:40], filesz)
	}
	putPhdr(0, elfPTNote, uint64(notesOff), 0, uint64(len(notes)))
	putPhdr(1, elfPTLoad, uint64(stackOff), stackVA, uint64(stackSize))
	copy(out[notesOff:], notes)
	copy(out[stackOff:], stack)
	return out
}

func appendNote(dst []byte, name string, typ uint32, desc []byte) []byte {
	nb := append([]byte(name), 0)
	var hdr [elfNoteHdr]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(nb)))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(len(desc)))
	binary.LittleEndian.PutUint32(hdr[8:12], typ)
	dst = append(dst, hdr[:]...)
	dst = append(dst, nb...)
	for len(dst)%4 != 0 {
		dst = append(dst, 0)
	}
	dst = append(dst, desc...)
	for len(dst)%4 != 0 {
		dst = append(dst, 0)
	}
	return dst
}

func TestOpenELFCoreDetails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core")
	if err := os.WriteFile(path, buildELFCoreNotes(), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	d := c.Details
	if d == nil {
		t.Fatal("Details = nil")
	}
	if d.OS != "linux" || d.Arch != "x86-64" {
		t.Fatalf("os/arch = %q/%q", d.OS, d.Arch)
	}
	if d.Process != "gohexcore" {
		t.Fatalf("process = %q", d.Process)
	}
	if len(d.Threads) != 1 {
		t.Fatalf("threads = %d", len(d.Threads))
	}
	th := d.Threads[0]
	if th.ID != 77 {
		t.Fatalf("thread id = %d", th.ID)
	}
	if th.Registers["rip"] != 0x402000 || th.Registers["rbp"] != 0x7FFE0100 || th.Registers["r8"] != 0xAA {
		t.Fatalf("registers = %v", th.Registers)
	}
	if len(d.Modules) != 2 {
		t.Fatalf("modules = %+v", d.Modules)
	}
	if d.Modules[0].Name != "app" || d.Modules[0].Base != 0x400000 || d.Modules[0].Size != 0x3000 {
		t.Fatalf("module[0] = %+v", d.Modules[0])
	}
	if d.Modules[1].Path != "/lib/libc.so.6" {
		t.Fatalf("module[1] = %+v", d.Modules[1])
	}
}

func TestWalkStackELFCore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core")
	if err := os.WriteFile(path, buildELFCoreNotes(), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := c.WalkStack(path, 77)
	if err != nil {
		t.Fatalf("WalkStack: %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("frames = %+v", frames)
	}
	if frames[0].Addr != 0x402000 || frames[1].Addr != 0x401010 || frames[2].Addr != 0x401020 {
		t.Fatalf("frame addrs = %#x %#x %#x", frames[0].Addr, frames[1].Addr, frames[2].Addr)
	}
}

// --- hibernation ------------------------------------------------------------

func TestOpenHiber(t *testing.T) {
	var buf bytes.Buffer
	for i := 0; i < 3; i++ {
		p := make([]byte, hiberPageSize)
		copy(p, "HIBR")
		binary.LittleEndian.PutUint32(p[4:8], 5)
		buf.Write(p)
	}
	// Trailing garbage is not part of the inventory.
	buf.Write([]byte("not a page"))
	path := filepath.Join(t.TempDir(), "hiberfil.sys")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if c.Format != FormatHiber {
		t.Fatalf("Format = %q", c.Format)
	}
	if c.HasMap {
		t.Fatal("hiber should have no address map")
	}
	if c.Hiber == nil || c.Hiber.Pages != 3 || c.Hiber.PageSize != hiberPageSize {
		t.Fatalf("hiber = %+v", c.Hiber)
	}
	if len(c.Hiber.Versions) != 1 || c.Hiber.Versions[0] != "v5 x3" {
		t.Fatalf("versions = %v", c.Hiber.Versions)
	}
}

func TestOpenHiberRejectsOtherMagic(t *testing.T) {
	data := append([]byte("PAGEDUMP"), make([]byte, 64)...)
	path := filepath.Join(t.TempDir(), "x.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("PAGEDUMP file should hit the 32-bit unsupported path, not raw")
	}
}

// --- Windows dump bugcheck --------------------------------------------------

func TestParseWinDumpBugCheck(t *testing.T) {
	hdr := make([]byte, 0x60)
	copy(hdr[0:8], "PAGEDU64")
	binary.LittleEndian.PutUint32(hdr[0x38:0x3C], 0x50) // PAGE_FAULT_IN_NONPAGED_AREA
	binary.LittleEndian.PutUint64(hdr[0x40:0x48], 0x41414141)
	binary.LittleEndian.PutUint64(hdr[0x48:0x50], 0x42424242)
	bc := parseWinDumpBugCheck(bytes.NewReader(hdr))
	if bc.Code != 0x50 {
		t.Fatalf("code = %#x", bc.Code)
	}
	if bc.Desc != "PAGE_FAULT_IN_NONPAGED_AREA" {
		t.Fatalf("desc = %q", bc.Desc)
	}
	if bc.Params[0] != 0x41414141 || bc.Params[1] != 0x42424242 {
		t.Fatalf("params = %v", bc.Params)
	}
}

// --- module diff -------------------------------------------------------------

func TestDiffModules(t *testing.T) {
	a := &Details{Modules: []Module{
		{Name: "a.exe", Base: 0x400000, Size: 0x1000},
		{Name: "b.dll", Base: 0x500000, Size: 0x2000},
	}}
	b := &Details{Modules: []Module{
		{Name: "a.exe", Base: 0x400000, Size: 0x1000},
		{Name: "c.dll", Base: 0x600000, Size: 0x1000},
	}}
	d := DiffModules(a, b)
	if d.Common != 1 || len(d.OnlyA) != 1 || len(d.OnlyB) != 1 {
		t.Fatalf("diff = %+v", d)
	}
	if d.OnlyA[0].Name != "b.dll" || d.OnlyB[0].Name != "c.dll" {
		t.Fatalf("diff = %+v", d)
	}
	if DiffModules(nil, b).Common != 0 {
		t.Fatal("nil details should diff to empty")
	}
}

// --- context decoding --------------------------------------------------------

func TestParseContextI386(t *testing.T) {
	ctx := make([]byte, contextI386Size)
	binary.LittleEndian.PutUint32(ctx[ctxI386Eip:], 0x401000)
	binary.LittleEndian.PutUint32(ctx[ctxI386Esp:], 0x12FF00)
	binary.LittleEndian.PutUint32(ctx[ctxI386Ebp:], 0x12FF80)
	m := parseContext(ctx, "x86")
	if m["eip"] != 0x401000 || m["esp"] != 0x12FF00 || m["ebp"] != 0x12FF80 {
		t.Fatalf("registers = %v", m)
	}
	if parseContext(ctx, "arm64") != nil {
		t.Fatal("arm64 should stay undecoded")
	}
}
