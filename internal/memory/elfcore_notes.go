package memory

import (
	"encoding/binary"
	"errors"
	"sort"
	"strings"
)

// ELF core note types (linux/core.h).
const (
	elfNotePRStatus  = 1
	elfNotePRPSInfo  = 3
	elfNoteFile      = 0x46494C45 // "FILE"
	elfPTNote        = 4
	elfNoteHdr       = 12 // namesz + descsz + type
	elf64PRStatusOff = 232 // offsetof(struct elf_prstatus, pr_regs) amd64
	elf32PRStatusOff = 188 // offsetof(struct elf_prstatus, pr_regs) i386
	elf64PRPidOff    = 152 // offsetof(struct elf_prstatus, pr_pid) amd64
	elf32PRPidOff    = 140 // offsetof(struct elf_prstatus, pr_pid) i386
	elfPRPSNameOff   = 32  // offsetof(struct elf_prpsinfo, pr_fname)
	elfPRPSNameLen   = 16
	maxNotes         = 512
)

// amd64 gregset order (sys/ucontext.h).
var amd64Gregs = []string{
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
	"rdi", "rsi", "rbp", "rbx", "rdx", "rax", "rcx", "rsp",
	"rip", "efl", "cs", "gs", "fs", "ss", "err", "trapno", "oldmask", "cr2",
}

// i386 gregset order.
var i386Gregs = []string{
	"ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "xds", "xes", "xfs", "xgs",
	"orig_eax", "eip", "xcs", "efl", "uesp", "xss",
}

// parseELFDetails walks the PT_NOTE segments of an ELF core and decodes
// NT_PRSTATUS (threads + registers), NT_PRPSINFO (process name) and
// NT_FILE (mapped files → modules). Errors degrade to a partial Details.
func parseELFDetails(f readerAtSize, class byte) (*Details, error) {
	is64 := class == elfClass64
	ehdrLen := elfEhdr32
	if is64 {
		ehdrLen = elfEhdr64
	}
	ehdr := make([]byte, ehdrLen)
	if _, err := f.ReadAt(ehdr, 0); err != nil {
		return nil, err
	}
	var phoff uint64
	var phentsize, phnum int
	if is64 {
		phoff = binary.LittleEndian.Uint64(ehdr[32:40])
		phentsize = int(binary.LittleEndian.Uint16(ehdr[54:56]))
		phnum = int(binary.LittleEndian.Uint16(ehdr[56:58]))
	} else {
		phoff = uint64(binary.LittleEndian.Uint32(ehdr[28:32]))
		phentsize = int(binary.LittleEndian.Uint16(ehdr[42:44]))
		phnum = int(binary.LittleEndian.Uint16(ehdr[44:46]))
	}
	if phnum == 0 || phnum > maxNotes {
		return nil, errors.New("memory: implausible ELF program header count")
	}
	dirBytes := phnum * phentsize
	phdrs := make([]byte, dirBytes)
	if _, err := f.ReadAt(phdrs, int64(phoff)); err != nil {
		return nil, err
	}

	d := &Details{OS: "linux"}
	if is64 {
		d.Arch = "x86-64"
	} else {
		d.Arch = "x86"
	}

	noteCount := 0
	for i := 0; i < phnum && noteCount < maxNotes; i++ {
		p := phdrs[i*phentsize : (i+1)*phentsize]
		if binary.LittleEndian.Uint32(p[0:4]) != elfPTNote {
			continue
		}
		var off, notesz uint64
		if is64 {
			off = binary.LittleEndian.Uint64(p[8:16])
			notesz = binary.LittleEndian.Uint64(p[32:40])
		} else {
			off = uint64(binary.LittleEndian.Uint32(p[4:8]))
			notesz = uint64(binary.LittleEndian.Uint32(p[16:20]))
		}
		if notesz == 0 || notesz > 64<<20 {
			continue // guard against corrupt headers
		}
		blob := make([]byte, notesz)
		if _, err := f.ReadAt(blob, int64(off)); err != nil {
			continue
		}
		parseELFNoteBlob(blob, d)
		noteCount++
	}
	sort.Slice(d.Modules, func(i, j int) bool { return d.Modules[i].Base < d.Modules[j].Base })
	sort.Slice(d.Threads, func(i, j int) bool { return d.Threads[i].ID < d.Threads[j].ID })
	return d, nil
}

// parseELFNoteBlob walks one concatenated note region.
func parseELFNoteBlob(blob []byte, d *Details) {
	var pos int
	for pos+elfNoteHdr <= len(blob) {
		namesz := binary.LittleEndian.Uint32(blob[pos : pos+4])
		descsz := binary.LittleEndian.Uint32(blob[pos+4 : pos+8])
		typ := binary.LittleEndian.Uint32(blob[pos+8 : pos+12])
		if namesz > 1<<16 || descsz > 64<<20 {
			return // corrupt: stop walking this region
		}
		nameOff := pos + elfNoteHdr
		descOff := align4(nameOff + int(namesz))
		end := align4(descOff + int(descsz))
		if descOff > len(blob) || end > len(blob) || end < pos {
			return
		}
		name := ""
		if namesz > 0 && nameOff+int(namesz) <= len(blob) {
			n := blob[nameOff : nameOff+int(namesz)]
			if i := indexByte(n, 0); i >= 0 {
				n = n[:i]
			}
			name = string(n)
		}
		desc := blob[descOff:end]
		switch {
		case typ == elfNotePRStatus && name == "CORE":
			d.Threads = append(d.Threads, parsePRStatus(desc, d.Arch))
		case typ == elfNotePRPSInfo && name == "CORE":
			if d.Process == "" {
				d.Process = parsePRPSInfo(desc)
			}
		case typ == elfNoteFile && name == "CORE":
			d.Modules = append(d.Modules, parseNTFile(desc, d.Arch)...)
		}
		pos = end
	}
}

func align4(n int) int { return (n + 3) &^ 3 }

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// parsePRStatus decodes one NT_PRSTATUS descriptor into a Thread.
func parsePRStatus(desc []byte, arch string) Thread {
	t := Thread{}
	var regsOff, pidOff int
	var gregs []string
	if arch == "x86-64" {
		regsOff, pidOff, gregs = elf64PRStatusOff, elf64PRPidOff, amd64Gregs
	} else {
		regsOff, pidOff, gregs = elf32PRStatusOff, elf32PRPidOff, i386Gregs
	}
	if pidOff+4 <= len(desc) {
		t.ID = binary.LittleEndian.Uint32(desc[pidOff:])
	}
	if regsOff < len(desc) {
		m := make(map[string]uint64, len(gregs))
		for i, name := range gregs {
			var off int
			var v uint64
			if arch == "x86-64" {
				off = regsOff + i*8
				if off+8 > len(desc) {
					break
				}
				v = binary.LittleEndian.Uint64(desc[off:])
			} else {
				off = regsOff + i*4
				if off+4 > len(desc) {
					break
				}
				v = uint64(binary.LittleEndian.Uint32(desc[off:]))
			}
			m[name] = v
		}
		if arch == "x86-64" {
			t.StackStart = m["rsp"]
		} else {
			t.StackStart = m["uesp"]
		}
		t.Registers = m
	}
	return t
}

// parsePRPSInfo extracts the 16-byte executable name.
func parsePRPSInfo(desc []byte) string {
	if elfPRPSNameOff+elfPRPSNameLen > len(desc) {
		return ""
	}
	raw := desc[elfPRPSNameOff : elfPRPSNameOff+elfPRPSNameLen]
	if i := indexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	return strings.TrimSpace(string(raw))
}

// parseNTFile decodes the NT_FILE note: count, page size, count address
// triples, then count NUL-separated absolute file names.
func parseNTFile(desc []byte, arch string) []Module {
	var count, pageSize uint64
	var pos int
	if arch == "x86-64" {
		if len(desc) < 16 {
			return nil
		}
		count = binary.LittleEndian.Uint64(desc[0:8])
		pageSize = binary.LittleEndian.Uint64(desc[8:16])
		pos = 16
	} else {
		if len(desc) < 8 {
			return nil
		}
		count = uint64(binary.LittleEndian.Uint32(desc[0:4]))
		pageSize = uint64(binary.LittleEndian.Uint32(desc[4:8]))
		pos = 8
	}
	if count == 0 || count > maxSegments {
		return nil
	}
	if pageSize == 0 || pageSize > 1<<30 {
		return nil // implausible page size: refuse to trust the table
	}
	var triples int
	if arch == "x86-64" {
		triples = 24
	} else {
		triples = 12
	}
	tableEnd := pos + int(count)*triples
	if tableEnd > len(desc) {
		return nil
	}
	type triple struct{ start, end, ofs uint64 }
	ts := make([]triple, count)
	for i := uint64(0); i < count; i++ {
		p := desc[pos+int(i)*triples:]
		if arch == "x86-64" {
			ts[i] = triple{
				start: binary.LittleEndian.Uint64(p[0:8]),
				end:   binary.LittleEndian.Uint64(p[8:16]),
				ofs:   binary.LittleEndian.Uint64(p[16:24]),
			}
		} else {
			ts[i] = triple{
				start: uint64(binary.LittleEndian.Uint32(p[0:4])),
				end:   uint64(binary.LittleEndian.Uint32(p[4:8])),
				ofs:   uint64(binary.LittleEndian.Uint32(p[8:12])),
			}
		}
	}
	// Filenames: count NUL-terminated strings.
	names := make([]string, 0, count)
	rest := desc[tableEnd:]
	for i := uint64(0); i < count && len(rest) > 0; i++ {
		n := indexByte(rest, 0)
		if n < 0 {
			break
		}
		names = append(names, string(rest[:n]))
		rest = rest[n+1:]
	}
	var mods []Module
	for i := range ts {
		if ts[i].end <= ts[i].start {
			continue
		}
		m := Module{
			Base: ts[i].start,
			Size: ts[i].end - ts[i].start,
		}
		if i < len(names) {
			m.Path = names[i]
			m.Name = baseName(names[i])
		}
		// Skip anonymous mappings and page-size-only offsets noise:
		// keep file-backed mappings plus the executable's own segments.
		if m.Path != "" && ts[i].ofs == 0 {
			mods = append(mods, m)
		}
	}
	return mods
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 && i+1 < len(p) {
		return p[i+1:]
	}
	return p
}
