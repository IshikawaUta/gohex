package memory

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"unicode/utf16"
)

// Minidump stream types parsed for details.
const (
	mdmpStreamThreadList   = 3
	mdmpStreamModuleList   = 4
	mdmpStreamException    = 6
	mdmpStreamSystemInfo   = 7
	mdmpStreamUnloadedMods = 14
)

// MINIDUMP structures (little-endian, packed).
const (
	mdmpModuleEnt   = 108 // MINIDUMP_MODULE
	mdmpThreadEnt   = 48  // MINIDUMP_THREAD
	mdmpExceptionSt = 168 // MINIDUMP_EXCEPTION_STREAM
	mdmpSysInfoMin  = 56  // MINIDUMP_SYSTEM_INFO minimum
)

// CONTEXT sizes for the architectures whose register sets are decoded.
const (
	contextAmd64Size = 1232 // sizeof(CONTEXT) x64
	contextI386Size  = 716  // sizeof(CONTEXT) x86
)

// CONTEXT_AMD64 general-purpose register offsets from the context start
// (winnt.h: 6 home fields + flags + segs + debug regs precede the GPRs).
const (
	ctxAmd64Rax = 0x78
	ctxAmd64Rcx = 0x80
	ctxAmd64Rdx = 0x88
	ctxAmd64Rbx = 0x90
	ctxAmd64Rsp = 0x98
	ctxAmd64Rbp = 0xA0
	ctxAmd64Rsi = 0xA8
	ctxAmd64Rdi = 0xB0
	ctxAmd64R8  = 0xB8
	ctxAmd64R9  = 0xC0
	ctxAmd64R10 = 0xC8
	ctxAmd64R11 = 0xD0
	ctxAmd64R12 = 0xD8
	ctxAmd64R13 = 0xE0
	ctxAmd64R14 = 0xE8
	ctxAmd64R15 = 0xF0
	ctxAmd64Rip = 0xF8
)

// CONTEXT_I386 general-purpose register offsets from the context start
// (winnt.h: flags + debug regs + FLOATING_SAVE_AREA precede the GPRs).
const (
	ctxI386Edi = 0x9C
	ctxI386Esi = 0xA0
	ctxI386Ebx = 0xA4
	ctxI386Edx = 0xA8
	ctxI386Ecx = 0xAC
	ctxI386Eax = 0xB0
	ctxI386Ebp = 0xB4
	ctxI386Eip = 0xB8
	ctxI386Efl = 0xC0
	ctxI386Esp = 0xC4
)

// PROCESSOR_ARCHITECTURE values from MINIDUMP_SYSTEM_INFO.
const (
	mdmpArchIntel  = 0
	mdmpArchAMD64  = 9
	mdmpArchARM64  = 12
	mdmpArchUnknown = 0xFFFF
)

type mdmpStreamEnt struct {
	typ  uint32
	size uint32
	rva  uint32
}

// mdmpDirectory reads and validates the minidump stream directory.
func mdmpDirectory(f readerAtSize, size int64) ([]mdmpStreamEnt, error) {
	if size < mdmpHeaderSize {
		return nil, fmt.Errorf("memory: truncated minidump header (%d bytes)", size)
	}
	hdr := make([]byte, mdmpHeaderSize)
	if _, err := f.ReadAt(hdr, 0); err != nil {
		return nil, err
	}
	nStreams := binary.LittleEndian.Uint32(hdr[8:12])
	dirRVA := binary.LittleEndian.Uint32(hdr[12:16])
	if nStreams > maxSegments {
		return nil, fmt.Errorf("memory: minidump has %d streams, more than %d", nStreams, maxSegments)
	}
	dirBytes := uint64(nStreams) * uint64(mdmpDirEnt)
	if uint64(dirRVA)+dirBytes > uint64(size) {
		return nil, errors.New("memory: minidump stream directory extends past end of file")
	}
	buf := make([]byte, int(dirBytes))
	if _, err := f.ReadAt(buf, int64(dirRVA)); err != nil {
		return nil, err
	}
	ents := make([]mdmpStreamEnt, nStreams)
	for i := range ents {
		p := buf[i*12 : (i+1)*12]
		ents[i] = mdmpStreamEnt{
			typ:  binary.LittleEndian.Uint32(p[0:4]),
			size: binary.LittleEndian.Uint32(p[4:8]),
			rva:  binary.LittleEndian.Uint32(p[8:12]),
		}
		if uint64(ents[i].rva)+uint64(ents[i].size) > uint64(size) {
			return nil, fmt.Errorf("memory: minidump stream %d extends past end of file", ents[i].typ)
		}
	}
	return ents, nil
}

func findStream(ents []mdmpStreamEnt, typ uint32) (mdmpStreamEnt, bool) {
	for _, e := range ents {
		if e.typ == typ && e.size > 0 {
			return e, true
		}
	}
	return mdmpStreamEnt{}, false
}

// readStream loads a stream's bytes.
func readStream(f readerAtSize, e mdmpStreamEnt) ([]byte, error) {
	buf := make([]byte, e.size)
	if _, err := f.ReadAt(buf, int64(e.rva)); err != nil {
		return nil, err
	}
	return buf, nil
}

// readMdmpString decodes a MINIDUMP_STRING (ULONG length + UTF-16 data).
func readMdmpString(f readerAtSize, size int64, rva uint32) string {
	if rva == 0 || uint64(rva)+4 > uint64(size) {
		return ""
	}
	var lb [4]byte
	if _, err := f.ReadAt(lb[:], int64(rva)); err != nil {
		return ""
	}
	n := binary.LittleEndian.Uint32(lb[:])
	if n == 0 || n > 32<<10 || uint64(rva)+4+uint64(n) > uint64(size) {
		return ""
	}
	raw := make([]byte, n)
	if _, err := f.ReadAt(raw, int64(rva)+4); err != nil {
		return ""
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return string(utf16.Decode(u))
}

// parseMdmpDetails walks the stream directory and decodes SystemInfo,
// ModuleList, ThreadList (with CONTEXT registers) and ExceptionStream.
// The directory walk is duplicated from parseMinidump on purpose: the
// segment pass and the details pass have different failure policies
// (segments are fatal, details are best-effort).
func parseMdmpDetails(f readerAtSize, size int64) (*Details, error) {
	ents, err := mdmpDirectory(f, size)
	if err != nil {
		return nil, err
	}
	d := &Details{}

	if e, ok := findStream(ents, mdmpStreamSystemInfo); ok {
		parseMdmpSystemInfo(f, e, d)
	}
	if e, ok := findStream(ents, mdmpStreamModuleList); ok {
		mods, err := parseMdmpModules(f, size, e)
		if err == nil {
			d.Modules = mods
		}
	}
	if e, ok := findStream(ents, mdmpStreamThreadList); ok {
		ths, err := parseMdmpThreads(f, size, e, d.Arch)
		if err == nil {
			d.Threads = ths
		}
	}
	if e, ok := findStream(ents, mdmpStreamException); ok {
		exc, err := parseMdmpException(f, size, e)
		if err == nil {
			d.Exception = exc
		}
	}
	return d, nil
}

func parseMdmpSystemInfo(f readerAtSize, e mdmpStreamEnt, d *Details) {
	buf, err := readStream(f, e)
	if err != nil || len(buf) < mdmpSysInfoMin {
		return
	}
	arch := binary.LittleEndian.Uint16(buf[0:2])
	switch arch {
	case mdmpArchAMD64:
		d.Arch = "x86-64"
		d.OS = "windows"
	case mdmpArchIntel:
		d.Arch = "x86"
		d.OS = "windows"
	case mdmpArchARM64:
		d.Arch = "arm64"
		d.OS = "windows"
	default:
		d.Arch = fmt.Sprintf("unknown(%d)", arch)
		d.OS = "windows"
	}
}

func parseMdmpModules(f readerAtSize, size int64, e mdmpStreamEnt) ([]Module, error) {
	buf, err := readStream(f, e)
	if err != nil || len(buf) < 4 {
		return nil, errors.New("memory: truncated minidump ModuleList")
	}
	count := binary.LittleEndian.Uint32(buf[0:4])
	if count > maxSegments {
		return nil, fmt.Errorf("memory: minidump has %d modules, more than %d", count, maxSegments)
	}
	if uint64(count)*mdmpModuleEnt+4 > uint64(len(buf)) {
		return nil, errors.New("memory: minidump ModuleList table overflows stream")
	}
	mods := make([]Module, 0, count)
	for i := uint32(0); i < count; i++ {
		p := buf[4+i*mdmpModuleEnt:]
		m := Module{
			Base: binary.LittleEndian.Uint64(p[0:8]),
			Size: uint64(binary.LittleEndian.Uint32(p[8:12])),
			Name: readMdmpString(f, size, binary.LittleEndian.Uint32(p[20:24])),
		}
		mods = append(mods, m)
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Base < mods[j].Base })
	return mods, nil
}

func parseMdmpThreads(f readerAtSize, size int64, e mdmpStreamEnt, arch string) ([]Thread, error) {
	buf, err := readStream(f, e)
	if err != nil || len(buf) < 4 {
		return nil, errors.New("memory: truncated minidump ThreadList")
	}
	count := binary.LittleEndian.Uint32(buf[0:4])
	if count > maxSegments {
		return nil, fmt.Errorf("memory: minidump has %d threads, more than %d", count, maxSegments)
	}
	if uint64(count)*mdmpThreadEnt+4 > uint64(len(buf)) {
		return nil, errors.New("memory: minidump ThreadList table overflows stream")
	}
	ths := make([]Thread, 0, count)
	for i := uint32(0); i < count; i++ {
		p := buf[4+i*mdmpThreadEnt:]
		t := Thread{
			ID:  binary.LittleEndian.Uint32(p[0:4]),
			Teb: binary.LittleEndian.Uint64(p[16:24]),
		}
		// MINIDUMP_MEMORY_DESCRIPTOR: stack range at p[24:40].
		t.StackStart = binary.LittleEndian.Uint64(p[24:32])
		stackSize := binary.LittleEndian.Uint32(p[32:36])
		if t.StackStart != 0 && stackSize != 0 {
			t.StackEnd = t.StackStart + uint64(stackSize)
		}
		// ThreadContext MINIDUMP_LOCATION at p[40:48].
		ctxSize := binary.LittleEndian.Uint32(p[40:44])
		ctxRVA := binary.LittleEndian.Uint32(p[44:48])
		if ctxRVA != 0 && ctxSize > 0 && uint64(ctxRVA)+uint64(ctxSize) <= uint64(size) {
			ctx := make([]byte, ctxSize)
			if _, err := f.ReadAt(ctx, int64(ctxRVA)); err == nil {
				t.Registers = parseContext(ctx, arch)
			}
		}
		ths = append(ths, t)
	}
	sort.Slice(ths, func(i, j int) bool { return ths[i].ID < ths[j].ID })
	return ths, nil
}

// parseContext decodes a CONTEXT structure for the supported
// architectures. ARM64 contexts are not decoded (registers stay nil).
func parseContext(ctx []byte, arch string) map[string]uint64 {
	switch arch {
	case "x86-64":
		if len(ctx) < ctxAmd64Rip+8 {
			return nil
		}
		u := func(off int) uint64 { return binary.LittleEndian.Uint64(ctx[off : off+8]) }
		return map[string]uint64{
			"rax": u(ctxAmd64Rax), "rcx": u(ctxAmd64Rcx), "rdx": u(ctxAmd64Rdx),
			"rbx": u(ctxAmd64Rbx), "rsp": u(ctxAmd64Rsp), "rbp": u(ctxAmd64Rbp),
			"rsi": u(ctxAmd64Rsi), "rdi": u(ctxAmd64Rdi),
			"r8": u(ctxAmd64R8), "r9": u(ctxAmd64R9), "r10": u(ctxAmd64R10),
			"r11": u(ctxAmd64R11), "r12": u(ctxAmd64R12), "r13": u(ctxAmd64R13),
			"r14": u(ctxAmd64R14), "r15": u(ctxAmd64R15), "rip": u(ctxAmd64Rip),
		}
	case "x86":
		if len(ctx) < ctxI386Esp+4 {
			return nil
		}
		u := func(off int) uint64 { return uint64(binary.LittleEndian.Uint32(ctx[off : off+4])) }
		return map[string]uint64{
			"ebx": u(ctxI386Ebx), "ecx": u(ctxI386Ecx), "edx": u(ctxI386Edx),
			"esi": u(ctxI386Esi), "edi": u(ctxI386Edi), "ebp": u(ctxI386Ebp),
			"eax": u(ctxI386Eax), "eip": u(ctxI386Eip), "efl": u(ctxI386Efl),
			"esp": u(ctxI386Esp),
		}
	}
	return nil
}

func parseMdmpException(f readerAtSize, size int64, e mdmpStreamEnt) (*Exception, error) {
	_ = size
	buf, err := readStream(f, e)
	if err != nil || len(buf) < mdmpExceptionSt {
		return nil, errors.New("memory: truncated minidump ExceptionStream")
	}
	// MINIDUMP_EXCEPTION_STREAM: ThreadId u32, Alignment u32,
	// ExceptionRecord MINIDUMP_EXCEPTION (at 8), ThreadContext LOCATION.
	rec := buf[8:]
	code := binary.LittleEndian.Uint32(rec[0:4])
	exc := &Exception{
		ThreadID: binary.LittleEndian.Uint32(buf[0:4]),
		Code:     code,
		Address:  binary.LittleEndian.Uint64(rec[16:24]),
		Desc:     DescribeException(code),
	}
	nParams := binary.LittleEndian.Uint32(rec[32:36])
	if nParams > 15 {
		nParams = 15
	}
	for i := uint32(0); i < nParams && i < 4; i++ {
		off := 40 + int(i)*8
		exc.Params[i] = binary.LittleEndian.Uint64(rec[off : off+8])
	}
	return exc, nil
}
