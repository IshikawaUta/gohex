// Package memory opens memory captures (RAM dumps and crash dumps)
// read-only and exposes their address segment layout, so callers can map an
// address onto a file offset and hand byte ranges to the hex view.
//
// Nothing in this package ever writes to the capture; every parse is
// strictly read-only.
//
// Supported capture formats:
//
//   - lime     LiME v1 range headers with uncompressed payloads (magic "EMiL");
//     addresses are physical
//   - elfcore  Linux ELF core dumps (ET_CORE, PT_LOAD segments); addresses
//     are virtual (p_vaddr)
//   - minidump Windows minidumps (magic "MDMP"); addresses are virtual,
//     from the Memory64List or MemoryList stream
//   - raw      headerless dump, exposed as one segment without an address map
//
// Windows kernel dumps (PAGEDU64/PAGEDUMP) and AVML captures are detected
// but not yet parsed (roadmap stage 4) and report an explicit error.
//
// Detection is magic-based (never extension-based), matching internal/image.
package memory

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
)

// Capture format identifiers returned by Capture.Format.
const (
	FormatLIME     = "lime"
	FormatELFCore  = "elf-core"
	FormatMinidump = "minidump"
	FormatRAW      = "raw"
)

const (
	limeMagic     = "EMiL" // 0x4C694D45 as uint32 little-endian
	limeHeader    = 32     // magic, version, start, end, reserved
	minidumpMagic = "MDMP"
	maxSegments   = 1 << 16
)

// ELF constants (little-endian only).
const (
	elfClass64  = 2
	elfDataLE   = 1
	elfTypeCore = 4
	elfPTLoad   = 1
	elfEhdr64   = 64
	elfEhdr32   = 52
	elfPhdr64   = 56
	elfPhdr32   = 32
)

// Minidump stream types used here.
const (
	mdmpHeaderSize      = 32 // signature, version, streams, dir RVA, checksum, timestamp, flags
	mdmpDirEnt          = 12 // stream type, data size, RVA
	mdmpStreamMemList64 = 7
	mdmpStreamMemList   = 5
)

// Segment is one contiguous run of memory stored in the capture. For mapped
// segments Length == AddrEnd - AddrStart; AddrEnd is exclusive. The address
// range is physical for LiME captures and virtual for ELF cores and
// minidumps. Captures without an address map (raw) carry Offset/Length only.
type Segment struct {
	Index     int    `json:"index"`
	Offset    int64  `json:"offset"` // byte offset of the payload in the file
	Length    int64  `json:"length"`
	AddrStart uint64 `json:"addrStart"`
	AddrEnd   uint64 `json:"addrEnd"` // exclusive; 0 when the format carries no map
}

// Capture is the parsed metadata of a memory capture file.
type Capture struct {
	Path     string    `json:"path"`
	Format   string    `json:"format"`
	Size     int64     `json:"size"`
	HasMap   bool      `json:"hasMap"` // address map available
	Segments []Segment `json:"segments"`
}

// Location is where an address lands inside the capture file.
type Location struct {
	Offset  int64 `json:"offset"`  // file offset of the address
	Segment int   `json:"segment"` // index of the covering segment
}

// Open parses the capture at path and returns its segment map. The file is
// closed before Open returns: only the parsed metadata is kept.
func Open(path string) (Capture, error) {
	f, err := os.Open(path)
	if err != nil {
		return Capture{}, fmt.Errorf("memory: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Capture{}, fmt.Errorf("memory: %w", err)
	}
	if st.IsDir() {
		return Capture{}, fmt.Errorf("memory: %s is a directory", path)
	}
	size := st.Size()
	if size == 0 {
		return Capture{}, errors.New("memory: empty capture")
	}

	var headBuf [18]byte // longest prefix needed: ELF e_type at 16..18
	n, _ := f.ReadAt(headBuf[:], 0)
	head := headBuf[:n]

	var segs []Segment
	format := FormatRAW
	switch {
	case bytes.HasPrefix(head, []byte(limeMagic)):
		format = FormatLIME
		if segs, err = parseLIME(f, size); err != nil {
			return Capture{}, err
		}
	case isELFHead(head):
		if err := checkELFSupported(head); err != nil {
			return Capture{}, err
		}
		if binary.LittleEndian.Uint16(head[16:18]) != elfTypeCore {
			return Capture{}, fmt.Errorf("memory: ELF file is not a core dump (type %d)", binary.LittleEndian.Uint16(head[16:18]))
		}
		format = FormatELFCore
		if segs, err = parseELFCore(f, size, head[4]); err != nil {
			return Capture{}, err
		}
	case bytes.HasPrefix(head, []byte(minidumpMagic)):
		format = FormatMinidump
		if segs, err = parseMinidump(f, size); err != nil {
			return Capture{}, err
		}
	case bytes.HasPrefix(head, []byte("PAGE")) &&
		(bytes.HasPrefix(head[4:], []byte("DU64")) || bytes.HasPrefix(head[4:], []byte("DUMP"))):
		return Capture{}, errors.New("memory: Windows kernel dumps (PAGEDU64/PAGEDUMP) are not yet supported (roadmap stage 4)")
	case bytes.HasPrefix(head, []byte("AVML")):
		return Capture{}, errors.New("memory: AVML captures are not yet supported (roadmap stage 4)")
	default:
		segs = []Segment{{Index: 0, Offset: 0, Length: size}}
	}
	return Capture{Path: path, Format: format, Size: size, HasMap: format != FormatRAW, Segments: segs}, nil
}

// Locate maps an address inside the capture onto a file offset. It fails for
// captures that carry no address map (raw dumps) and for addresses the
// capture does not cover.
func (c *Capture) Locate(addr int64) (Location, error) {
	if !c.HasMap {
		return Location{}, errors.New("memory: capture has no address map")
	}
	if addr < 0 {
		return Location{}, errors.New("memory: negative address")
	}
	for i := range c.Segments {
		s := &c.Segments[i]
		if uint64(addr) >= s.AddrStart && uint64(addr) < s.AddrEnd {
			return Location{Offset: s.Offset + int64(uint64(addr)-s.AddrStart), Segment: i}, nil
		}
	}
	return Location{}, fmt.Errorf("memory: address %#x is not covered by the capture", addr)
}

// --- LiME ------------------------------------------------------------------

// parseLIME walks the chain of LiME range headers: (32-byte header, payload
// of end-start+1 bytes) repeated until the end of the file.
func parseLIME(f io.ReaderAt, size int64) ([]Segment, error) {
	var segs []Segment
	var pos int64
	hdr := make([]byte, limeHeader)
	for pos < size {
		if size-pos < limeHeader {
			return nil, fmt.Errorf("memory: truncated LiME header at %d", pos)
		}
		if _, err := f.ReadAt(hdr, pos); err != nil {
			return nil, fmt.Errorf("memory: read LiME header at %d: %w", pos, err)
		}
		if string(hdr[:4]) != limeMagic {
			return nil, fmt.Errorf("memory: bad LiME magic at %d", pos)
		}
		if v := binary.LittleEndian.Uint32(hdr[4:8]); v != 1 {
			return nil, fmt.Errorf("memory: unsupported LiME version %d at %d", v, pos)
		}
		start := binary.LittleEndian.Uint64(hdr[8:16])
		end := binary.LittleEndian.Uint64(hdr[16:24]) // inclusive
		if start > end {
			return nil, fmt.Errorf("memory: segment %d has start %#x beyond end %#x", len(segs), start, end)
		}
		if end == math.MaxUint64 {
			return nil, fmt.Errorf("memory: segment %d has implausible end address", len(segs))
		}
		span := end - start // payload is span+1 bytes
		dataStart := pos + limeHeader
		if span >= uint64(size) || span+1 > uint64(size-dataStart) {
			return nil, fmt.Errorf("memory: segment %d payload truncated at %d", len(segs), pos)
		}
		length := int64(span + 1)
		segs = append(segs, Segment{
			Index:     len(segs),
			Offset:    dataStart,
			Length:    length,
			AddrStart: start,
			AddrEnd:   end + 1,
		})
		if len(segs) > maxSegments {
			return nil, fmt.Errorf("memory: more than %d LiME segments", maxSegments)
		}
		pos = dataStart + length
	}
	if len(segs) == 0 {
		return nil, errors.New("memory: no LiME segments")
	}
	return segs, nil
}

// --- ELF core --------------------------------------------------------------

// isELFHead reports whether head begins with the ELF magic. Class, data
// encoding and e_type are validated by checkELFSupported / parseELFCore.
func isELFHead(head []byte) bool {
	return bytes.HasPrefix(head, []byte{0x7F, 'E', 'L', 'F'})
}

// checkELFSupported rejects ELF files this parser cannot honestly read:
// wrong class, big-endian, or a truncated identification block.
func checkELFSupported(head []byte) error {
	if len(head) < 18 {
		return errors.New("memory: truncated ELF header")
	}
	if head[5] != elfDataLE {
		return errors.New("memory: big-endian ELF core is not supported")
	}
	if head[4] != 1 && head[4] != elfClass64 {
		return fmt.Errorf("memory: invalid ELF class %d", head[4])
	}
	return nil
}

// parseELFCore reads the program headers of a little-endian ELF core and
// turns every PT_LOAD segment with file bytes into a Segment. Segments are
// returned sorted by virtual address. A segment whose payload runs past the
// end of a truncated file is clamped to the bytes that exist.
func parseELFCore(f io.ReaderAt, size int64, class byte) ([]Segment, error) {
	is64 := class == elfClass64
	ehdrLen := int64(elfEhdr32)
	if is64 {
		ehdrLen = elfEhdr64
	}
	if size < ehdrLen {
		return nil, fmt.Errorf("memory: truncated ELF header (%d bytes)", size)
	}
	ehdr := make([]byte, ehdrLen)
	if _, err := f.ReadAt(ehdr, 0); err != nil {
		return nil, fmt.Errorf("memory: read ELF header: %w", err)
	}

	var phoff uint64
	var phentsize, phnum int
	if is64 {
		phoff = binary.LittleEndian.Uint64(ehdr[32:40])
		phentsize = int(binary.LittleEndian.Uint16(ehdr[54:56]))
		phnum = int(binary.LittleEndian.Uint16(ehdr[56:58]))
		if phentsize != elfPhdr64 {
			return nil, fmt.Errorf("memory: ELF program header size %d, want %d", phentsize, elfPhdr64)
		}
	} else {
		phoff = uint64(binary.LittleEndian.Uint32(ehdr[28:32]))
		phentsize = int(binary.LittleEndian.Uint16(ehdr[42:44]))
		phnum = int(binary.LittleEndian.Uint16(ehdr[44:46]))
		if phentsize != elfPhdr32 {
			return nil, fmt.Errorf("memory: ELF program header size %d, want %d", phentsize, elfPhdr32)
		}
	}
	if phnum == 0 {
		return nil, errors.New("memory: ELF core contains no program headers")
	}
	if phnum > maxSegments {
		return nil, fmt.Errorf("memory: ELF core has %d program headers, more than %d", phnum, maxSegments)
	}
	dirBytes := uint64(phnum) * uint64(phentsize)
	if phoff > math.MaxUint64-dirBytes || phoff+dirBytes > uint64(size) {
		return nil, fmt.Errorf("memory: ELF program headers extend past end of file")
	}

	phdrs := make([]byte, int(dirBytes))
	if _, err := f.ReadAt(phdrs, int64(phoff)); err != nil {
		return nil, fmt.Errorf("memory: read ELF program headers: %w", err)
	}

	var segs []Segment
	for i := 0; i < phnum; i++ {
		p := phdrs[i*phentsize : (i+1)*phentsize]
		pType := binary.LittleEndian.Uint32(p[0:4])
		if pType != elfPTLoad {
			continue
		}
		var pOffset, pVaddr, pFilesz uint64
		if is64 {
			pOffset = binary.LittleEndian.Uint64(p[8:16])
			pVaddr = binary.LittleEndian.Uint64(p[16:24])
			pFilesz = binary.LittleEndian.Uint64(p[32:40])
		} else {
			pOffset = uint64(binary.LittleEndian.Uint32(p[4:8]))
			pVaddr = uint64(binary.LittleEndian.Uint32(p[8:12]))
			pFilesz = uint64(binary.LittleEndian.Uint32(p[16:20]))
		}
		if pFilesz == 0 {
			continue // pure BSS, no bytes in the file
		}
		if pVaddr > math.MaxUint64-pFilesz {
			return nil, fmt.Errorf("memory: ELF segment %d has implausible address range", len(segs))
		}
		if pOffset > math.MaxInt64 {
			return nil, fmt.Errorf("memory: ELF segment %d has implausible file offset", len(segs))
		}
		if pOffset >= uint64(size) {
			return nil, fmt.Errorf("memory: ELF segment %d starts past end of file", len(segs))
		}
		length := pFilesz
		if pOffset+length > uint64(size) { // truncated dump: clamp to what exists
			length = uint64(size) - pOffset
		}
		segs = append(segs, Segment{
			Index:     len(segs),
			Offset:    int64(pOffset),
			Length:    int64(length),
			AddrStart: pVaddr,
			AddrEnd:   pVaddr + length,
		})
		if len(segs) > maxSegments {
			return nil, fmt.Errorf("memory: more than %d ELF segments", maxSegments)
		}
	}
	if len(segs) == 0 {
		return nil, errors.New("memory: ELF core contains no loadable memory segments")
	}
	sortSegments(segs)
	return segs, nil
}

// --- Minidump --------------------------------------------------------------

// parseMinidump reads the stream directory and extracts the memory map from
// the Memory64ListStream (preferred, contiguous payload after the table) or,
// failing that, the classic MemoryListStream (separate buffer per range).
// Truncated ranges are clamped to the bytes that exist.
func parseMinidump(f io.ReaderAt, size int64) ([]Segment, error) {
	if size < mdmpHeaderSize {
		return nil, fmt.Errorf("memory: truncated minidump header (%d bytes)", size)
	}
	hdr := make([]byte, mdmpHeaderSize)
	if _, err := f.ReadAt(hdr, 0); err != nil {
		return nil, fmt.Errorf("memory: read minidump header: %w", err)
	}
	nStreams := uint64(binary.LittleEndian.Uint32(hdr[8:12]))
	dirRVA := uint64(binary.LittleEndian.Uint32(hdr[12:16]))
	if nStreams == 0 {
		return nil, errors.New("memory: minidump has no streams")
	}
	if nStreams > maxSegments {
		return nil, fmt.Errorf("memory: minidump has %d streams, more than %d", nStreams, maxSegments)
	}
	dirBytes := nStreams * mdmpDirEnt
	if dirRVA > math.MaxUint64-dirBytes || dirRVA+dirBytes > uint64(size) {
		return nil, errors.New("memory: minidump stream directory extends past end of file")
	}
	dir := make([]byte, int(dirBytes))
	if _, err := f.ReadAt(dir, int64(dirRVA)); err != nil {
		return nil, fmt.Errorf("memory: read minidump stream directory: %w", err)
	}

	var list64, list *mdmpRange
	for i := uint64(0); i < nStreams; i++ {
		e := dir[i*mdmpDirEnt : (i+1)*mdmpDirEnt]
		sType := binary.LittleEndian.Uint32(e[0:4])
		sSize := uint64(binary.LittleEndian.Uint32(e[4:8]))
		sRVA := uint64(binary.LittleEndian.Uint32(e[8:12]))
		if sRVA > math.MaxUint64-sSize || sRVA+sSize > uint64(size) {
			return nil, fmt.Errorf("memory: minidump stream %d extends past end of file", sType)
		}
		switch sType {
		case mdmpStreamMemList64:
			if list64 == nil {
				r, err := readMemList64(f, int64(sRVA), size)
				if err != nil {
					return nil, err
				}
				list64 = r
			}
		case mdmpStreamMemList:
			if list == nil {
				r, err := readMemList(f, int64(sRVA), size)
				if err != nil {
					return nil, err
				}
				list = r
			}
		}
	}
	src := list64
	if src == nil {
		src = list
	}
	if src == nil {
		return nil, errors.New("memory: minidump carries no memory streams")
	}
	if len(src.segs) == 0 {
		return nil, errors.New("memory: minidump memory stream is empty")
	}
	sortSegments(src.segs)
	return src.segs, nil
}

// mdmpRange is a parsed minidump memory descriptor list.
type mdmpRange struct {
	segs []Segment
}

// readMemList64 parses a Memory64ListStream: u64 range count, u64 base RVA
// of the concatenated payloads, then (start u64, size u64) per range.
func readMemList64(f io.ReaderAt, rva, size int64) (*mdmpRange, error) {
	var meta [16]byte
	if rva < 0 || rva+16 > size {
		return nil, errors.New("memory: truncated minidump Memory64List header")
	}
	if _, err := f.ReadAt(meta[:], rva); err != nil {
		return nil, fmt.Errorf("memory: read minidump Memory64List header: %w", err)
	}
	n := binary.LittleEndian.Uint64(meta[0:8])
	base := binary.LittleEndian.Uint64(meta[8:16])
	if n == 0 {
		return &mdmpRange{}, nil
	}
	if n > maxSegments {
		return nil, fmt.Errorf("memory: minidump has %d memory ranges, more than %d", n, maxSegments)
	}
	tableBytes := n * 16
	if uint64(rva)+16 > math.MaxUint64-tableBytes {
		return nil, errors.New("memory: minidump Memory64List table overflows")
	}
	tableOff := uint64(rva) + 16
	if tableOff+tableBytes > uint64(size) {
		return nil, errors.New("memory: truncated minidump Memory64List table")
	}
	table := make([]byte, int(tableBytes))
	if _, err := f.ReadAt(table, int64(tableOff)); err != nil {
		return nil, fmt.Errorf("memory: read minidump Memory64List table: %w", err)
	}
	out := &mdmpRange{segs: make([]Segment, 0, int(n))}
	pos := base
	for i := uint64(0); i < n; i++ {
		e := table[i*16 : (i+1)*16]
		start := binary.LittleEndian.Uint64(e[0:8])
		length := binary.LittleEndian.Uint64(e[8:16])
		if start > math.MaxUint64-length {
			return nil, fmt.Errorf("memory: minidump range %d has implausible address range", i)
		}
		if pos > math.MaxInt64 {
			return nil, fmt.Errorf("memory: minidump range %d has implausible file offset", i)
		}
		if pos < uint64(size) {
			l := length
			if pos+l > uint64(size) {
				l = uint64(size) - pos // truncated dump: clamp
			}
			if l > 0 {
				out.segs = append(out.segs, Segment{
					Index:     len(out.segs),
					Offset:    int64(pos),
					Length:    int64(l),
					AddrStart: start,
					AddrEnd:   start + l,
				})
			}
		}
		if pos > math.MaxUint64-length {
			break
		}
		pos += length
	}
	return out, nil
}

// readMemList parses a classic MemoryListStream: u32 range count, then
// (start u64, size u32, RVA u32) per range with payloads at their RVAs.
func readMemList(f io.ReaderAt, rva, size int64) (*mdmpRange, error) {
	var meta [4]byte
	if rva < 0 || rva+4 > size {
		return nil, errors.New("memory: truncated minidump MemoryList header")
	}
	if _, err := f.ReadAt(meta[:], rva); err != nil {
		return nil, fmt.Errorf("memory: read minidump MemoryList header: %w", err)
	}
	n := uint64(binary.LittleEndian.Uint32(meta[0:4]))
	if n == 0 {
		return &mdmpRange{}, nil
	}
	if n > maxSegments {
		return nil, fmt.Errorf("memory: minidump has %d memory ranges, more than %d", n, maxSegments)
	}
	tableBytes := n * 16
	tableOff := uint64(rva) + 4
	if tableOff+tableBytes > uint64(size) {
		return nil, errors.New("memory: truncated minidump MemoryList table")
	}
	table := make([]byte, int(tableBytes))
	if _, err := f.ReadAt(table, int64(tableOff)); err != nil {
		return nil, fmt.Errorf("memory: read minidump MemoryList table: %w", err)
	}
	out := &mdmpRange{}
	for i := uint64(0); i < n; i++ {
		e := table[i*16 : (i+1)*16]
		start := binary.LittleEndian.Uint64(e[0:8])
		length := uint64(binary.LittleEndian.Uint32(e[8:12]))
		bufRVA := uint64(binary.LittleEndian.Uint32(e[12:16]))
		if start > math.MaxUint64-length {
			return nil, fmt.Errorf("memory: minidump range %d has implausible address range", i)
		}
		if bufRVA > math.MaxInt64 {
			return nil, fmt.Errorf("memory: minidump range %d has implausible file offset", i)
		}
		if length == 0 || bufRVA >= uint64(size) {
			continue
		}
		l := length
		if bufRVA+l > uint64(size) {
			l = uint64(size) - bufRVA // truncated dump: clamp
		}
		out.segs = append(out.segs, Segment{
			Index:     len(out.segs),
			Offset:    int64(bufRVA),
			Length:    int64(l),
			AddrStart: start,
			AddrEnd:   start + l,
		})
	}
	return out, nil
}

// sortSegments orders segments by address and rewrites the index field.
func sortSegments(segs []Segment) {
	sort.Slice(segs, func(i, j int) bool { return segs[i].AddrStart < segs[j].AddrStart })
	for i := range segs {
		segs[i].Index = i
	}
}
