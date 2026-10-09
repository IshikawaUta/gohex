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
//   - avml     AVML v2 captures (magic "AVML", same 32-byte header as LiME)
//     with Snappy-framed compressed blocks; addresses are physical and the
//     payloads are exposed through Reader's uncompressed virtual view
//   - elfcore  Linux ELF core dumps (ET_CORE, PT_LOAD segments); addresses
//     are virtual (p_vaddr)
//   - minidump Windows minidumps (magic "MDMP"); addresses are virtual,
//     from the Memory64List or MemoryList stream
//   - windump  Windows 64-bit complete (DumpType 1) and bitmap (DumpType 5)
//     crash dumps (magic "PAGEDU64"); addresses are physical
//   - raw      headerless dump, exposed as one segment without an address map
//
// 32-bit Windows dumps (PAGEDUMP), Windows kernel/small dumps and Windows
// 8+ compressed kernel dumps are detected but not yet parsed (roadmap
// stage 4) and report an explicit error.
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
	FormatAVML     = "avml"
	FormatELFCore  = "elf-core"
	FormatMinidump = "minidump"
	FormatWinDump  = "windump"
	FormatRAW      = "raw"
)

const (
	limeMagic     = "EMiL" // 0x4C694D45 as uint32 little-endian
	limeHeader    = 32     // magic, version, start, end, reserved
	avmlMagic     = "AVML" // 0x4C4D5641 as uint32 little-endian
	avmlHeader    = 32     // same wire layout as LiME, version 2
	avmlMaxBlock  = 16 << 20
	minidumpMagic = "MDMP"
	maxSegments   = 1 << 16
)

// Windows 64-bit dump constants (layout per the DUMP_HEADER64 /
// _SUMMARY_DUMP structures).
const (
	winDumpPageSize   = 0x1000
	winDumpHeaderSize = 0x2000 // headerpages = 2 for 64-bit dumps
	winDumpTypeOff    = 3992
	winDumpPhysDesc   = 136 // _PHYSICAL_MEMORY_DESCRIPTOR64
	winDumpRunBase    = 16  // run array offset inside the descriptor
	winDumpSummary    = winDumpHeaderSize
	winDumpSumHdrSize = 32 // _SUMMARY_DUMP.HeaderSize
	winDumpSumBmpSize = 48 // _SUMMARY_DUMP.BitmapSize
	winDumpSumBuf     = 56 // _SUMMARY_DUMP.BufferLong
	winDumpTypeFull   = 1
	winDumpTypeBitmap = 5
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
// range is physical for LiME, AVML and Windows dumps and virtual for ELF
// cores and minidumps. Offset is the payload's byte offset in the file for
// uncompressed formats; for compressed captures (AVML) it is the dense
// virtual offset inside Reader's uncompressed view. Captures without an
// address map (raw) carry Offset/Length only.
type Segment struct {
	Index     int    `json:"index"`
	Offset    int64  `json:"offset"`
	Length    int64  `json:"length"`
	AddrStart uint64 `json:"addrStart"`
	AddrEnd   uint64 `json:"addrEnd"` // exclusive; 0 when the format carries no map
}

// Capture is the parsed metadata of a memory capture file.
type Capture struct {
	Path       string    `json:"path"`
	Format     string    `json:"format"`
	Size       int64     `json:"size"`
	HasMap     bool      `json:"hasMap"`     // address map available
	Compressed bool      `json:"compressed"` // payloads are compressed; use OpenReader
	Segments   []Segment `json:"segments"`

	blocks []compBlock // AVML only: compressed backing store per segment
}

// compBlock locates a segment's compressed payload in the file.
type compBlock struct {
	fileOff int64 // start of the snappy framed stream
	compLen int64 // stream length including the 8-byte trailer
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
	var blocks []compBlock
	format := FormatRAW
	switch {
	case bytes.HasPrefix(head, []byte(limeMagic)):
		format = FormatLIME
		if segs, err = parseLIME(f, size); err != nil {
			return Capture{}, err
		}
	case bytes.HasPrefix(head, []byte(avmlMagic)):
		format = FormatAVML
		if segs, blocks, err = parseAVML(f, size); err != nil {
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
	case bytes.HasPrefix(head, []byte("PAGE")) && bytes.HasPrefix(head[4:], []byte("DU64")):
		format = FormatWinDump
		if segs, err = parseWinDump(f, size); err != nil {
			return Capture{}, err
		}
	case bytes.HasPrefix(head, []byte("PAGE")) && bytes.HasPrefix(head[4:], []byte("DUMP")):
		return Capture{}, errors.New("memory: 32-bit Windows kernel dumps (PAGEDUMP) are not yet supported (roadmap stage 4)")
	default:
		segs = []Segment{{Index: 0, Offset: 0, Length: size}}
	}
	return Capture{
		Path:       path,
		Format:     format,
		Size:       size,
		HasMap:     format != FormatRAW,
		Compressed: format == FormatAVML,
		Segments:   segs,
		blocks:     blocks,
	}, nil
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

// --- AVML ------------------------------------------------------------------

// avmlPair keeps a segment together with its compressed backing store so
// both are reordered in lock-step when segments are sorted by address.
type avmlPair struct {
	seg     Segment
	fileOff int64 // start of the snappy framed stream
	compLen int64 // stream length including the 8-byte trailer
}

// parseAVML walks the chain of AVML v2 headers: (32-byte header, Snappy
// framed stream, 8-byte compressed-length trailer) repeated to the end of
// the file. All-zero blocks are elided by writers, so address gaps simply
// do not appear as segments. Segments come back sorted by address with
// dense virtual offsets; the returned blocks pair with them 1:1.
func parseAVML(f io.ReaderAt, size int64) ([]Segment, []compBlock, error) {
	var pairs []avmlPair
	var pos int64
	hdr := make([]byte, avmlHeader)
	for pos < size {
		if size-pos < avmlHeader {
			return nil, nil, fmt.Errorf("memory: truncated AVML header at %d", pos)
		}
		if _, err := f.ReadAt(hdr, pos); err != nil {
			return nil, nil, fmt.Errorf("memory: read AVML header at %d: %w", pos, err)
		}
		if string(hdr[:4]) != avmlMagic {
			return nil, nil, fmt.Errorf("memory: bad AVML magic at %d", pos)
		}
		if v := binary.LittleEndian.Uint32(hdr[4:8]); v != 2 {
			return nil, nil, fmt.Errorf("memory: unsupported AVML version %d at %d", v, pos)
		}
		start := binary.LittleEndian.Uint64(hdr[8:16])
		end := binary.LittleEndian.Uint64(hdr[16:24]) // inclusive
		if binary.LittleEndian.Uint64(hdr[24:32]) != 0 {
			return nil, nil, fmt.Errorf("memory: bad AVML padding at %d", pos)
		}
		if start > end {
			return nil, nil, fmt.Errorf("memory: block %d has start %#x beyond end %#x", len(pairs), start, end)
		}
		if end == math.MaxUint64 {
			return nil, nil, fmt.Errorf("memory: block %d has implausible end address", len(pairs))
		}
		uncomp := end - start + 1
		if uncomp > avmlMaxBlock {
			return nil, nil, fmt.Errorf("memory: block %d larger than %d bytes", len(pairs), avmlMaxBlock)
		}
		payload := pos + avmlHeader
		endPos, err := avmlStreamEnd(f, payload, size, int64(uncomp))
		if err != nil {
			return nil, nil, fmt.Errorf("memory: AVML block at %d: %w", pos, err)
		}
		var trailer [8]byte
		if _, err := f.ReadAt(trailer[:], endPos); err != nil {
			return nil, nil, fmt.Errorf("memory: truncated AVML trailer at %d", endPos)
		}
		if clen := binary.LittleEndian.Uint64(trailer[:]); clen != uint64(endPos-payload) {
			return nil, nil, fmt.Errorf("memory: bad AVML compressed-length trailer at %d", endPos)
		}
		pairs = append(pairs, avmlPair{
			seg: Segment{
				Index:     len(pairs),
				Length:    int64(uncomp),
				AddrStart: start,
				AddrEnd:   end + 1,
			},
			fileOff: payload,
			compLen: endPos + 8 - payload,
		})
		if len(pairs) > maxSegments {
			return nil, nil, fmt.Errorf("memory: more than %d AVML blocks", maxSegments)
		}
		pos = endPos + 8
	}
	if len(pairs) == 0 {
		return nil, nil, errors.New("memory: no AVML blocks")
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].seg.AddrStart < pairs[j].seg.AddrStart })
	segs := make([]Segment, len(pairs))
	blocks := make([]compBlock, len(pairs))
	var dense int64
	for i, p := range pairs {
		p.seg.Index = i
		p.seg.Offset = dense // dense virtual offset inside Reader's view
		dense += p.seg.Length
		segs[i] = p.seg
		blocks[i] = compBlock{fileOff: p.fileOff, compLen: p.compLen}
	}
	return segs, blocks, nil
}

// avmlStreamEnd walks the Snappy framed stream at start without
// decompressing it — chunk headers carry their own three-byte lengths —
// and returns the offset of the 8-byte AVML trailer that follows the last
// frame.
func avmlStreamEnd(f io.ReaderAt, start, size, uncomp int64) (int64, error) {
	var produced int64
	pos := start
	first := true
	var hdr [snappyChunkHdr]byte
	for produced < uncomp {
		if pos+snappyChunkHdr > size {
			return 0, errors.New("truncated snappy frame header")
		}
		if _, err := f.ReadAt(hdr[:], pos); err != nil {
			return 0, err
		}
		ctype := hdr[0]
		clen := int64(hdr[1]) | int64(hdr[2])<<8 | int64(hdr[3])<<16
		pos += snappyChunkHdr
		if pos+clen > size {
			return 0, errors.New("truncated snappy frame")
		}
		switch {
		case ctype == 0xFF: // stream identifier frame
			if clen != 6 {
				return 0, errors.New("bad snappy stream identifier")
			}
			var id [6]byte
			if _, err := f.ReadAt(id[:], pos); err != nil {
				return 0, err
			}
			if string(id[:]) != "sNaPpY" {
				return 0, errors.New("bad snappy stream identifier")
			}
			if first {
				first = false
			}
		case ctype == snappyChunkComp:
			if clen < 5 {
				return 0, errors.New("truncated snappy compressed frame")
			}
			var vb [10]byte
			n, _ := f.ReadAt(vb[:], pos+4)
			uLen, vn := binary.Uvarint(vb[:n])
			if vn <= 0 {
				return 0, errSnappyMalformed
			}
			produced += int64(uLen)
		case ctype == snappyChunkUncomp:
			if clen < 4 {
				return 0, errors.New("truncated snappy uncompressed frame")
			}
			produced += clen - 4
		case ctype >= snappyChunkSkippMin:
			// padding / reserved skippable; does not contribute output
		default:
			return 0, fmt.Errorf("unsupported snappy chunk type %#x", ctype)
		}
		if produced > uncomp {
			return 0, errors.New("snappy output exceeds declared block size")
		}
		pos += clen
		if first {
			return 0, errors.New("missing snappy stream identifier")
		}
		if produced == uncomp {
			if pos+8 > size {
				return 0, errors.New("truncated AVML trailer")
			}
			return pos, nil // parseAVML validates the trailer value
		}
	}
	return 0, errors.New("snappy stream did not reach the declared block size")
}

// --- Windows 64-bit crash dumps -------------------------------------------

// parseWinDump reads a Windows 64-bit crash dump (magic "PAGEDU64").
// DumpType 1 (complete dump) keeps the physical runs' pages back-to-back
// after the two header pages; DumpType 5 stores a summary header plus a
// page bitmap whose set bits map consecutive pages. Other dump types —
// kernel, small memory and Windows 8+ compressed dumps — are not yet
// supported.
func parseWinDump(f io.ReaderAt, size int64) ([]Segment, error) {
	if size < winDumpHeaderSize {
		return nil, fmt.Errorf("memory: truncated Windows dump header (%d bytes)", size)
	}
	var sec [9]byte
	if _, err := f.ReadAt(sec[:], winDumpHeaderSize); err == nil && string(sec[:]) == "CRASHDUMP" {
		return nil, errors.New("memory: Windows 8+ compressed kernel dumps are not yet supported (roadmap stage 4)")
	}
	hdr := make([]byte, winDumpHeaderSize)
	if _, err := f.ReadAt(hdr, 0); err != nil {
		return nil, fmt.Errorf("memory: read Windows dump header: %w", err)
	}
	switch dumpType := binary.LittleEndian.Uint32(hdr[winDumpTypeOff:]); dumpType {
	case winDumpTypeFull:
		return winDumpRuns(f, size, hdr)
	case winDumpTypeBitmap:
		return winDumpBitmap(f, size)
	default:
		return nil, fmt.Errorf("memory: unsupported Windows dump type %#x (kernel and small memory dumps are not yet supported)", dumpType)
	}
}

// winDumpRuns builds segments from the physical memory runs of a complete
// (DumpType 1) dump: after the two header pages the runs' pages follow in
// run order.
func winDumpRuns(f io.ReaderAt, size int64, hdr []byte) ([]Segment, error) {
	nRuns := uint64(binary.LittleEndian.Uint32(hdr[winDumpPhysDesc : winDumpPhysDesc+4]))
	if nRuns == 0 {
		return nil, errors.New("memory: Windows dump has no physical memory runs")
	}
	if winDumpPhysDesc+winDumpRunBase+int64(nRuns)*16 > int64(len(hdr)) {
		return nil, errors.New("memory: Windows dump run table exceeds the header")
	}
	var segs []Segment
	fileOff := int64(winDumpHeaderSize)
	for i := uint64(0); i < nRuns; i++ {
		e := hdr[winDumpPhysDesc+winDumpRunBase+int64(i)*16:]
		basePage := binary.LittleEndian.Uint64(e[0:8])
		pages := binary.LittleEndian.Uint64(e[8:16])
		if pages == 0 {
			continue
		}
		if basePage > math.MaxUint64/winDumpPageSize || pages > math.MaxUint64/winDumpPageSize {
			return nil, fmt.Errorf("memory: Windows dump run %d is implausible", i)
		}
		physStart := basePage * winDumpPageSize
		length := pages * winDumpPageSize
		if physStart > math.MaxUint64-length {
			return nil, fmt.Errorf("memory: Windows dump run %d overflows the address space", i)
		}
		if length > math.MaxInt64 {
			return nil, fmt.Errorf("memory: Windows dump run %d is too large", i)
		}
		if fileOff < size {
			l := length
			if fileOff+int64(l) > size { // truncated dump: clamp to what exists
				l = uint64(size - fileOff)
			}
			segs = append(segs, Segment{
				Index:     len(segs),
				Offset:    fileOff,
				Length:    int64(l),
				AddrStart: physStart,
				AddrEnd:   physStart + l,
			})
			if len(segs) > maxSegments {
				return nil, fmt.Errorf("memory: more than %d Windows dump segments", maxSegments)
			}
		}
		fileOff += int64(length) // positions follow the declared layout
		if fileOff < 0 {
			return nil, errors.New("memory: Windows dump layout overflows")
		}
	}
	if len(segs) == 0 {
		return nil, errors.New("memory: Windows dump contains no file bytes")
	}
	sortSegments(segs)
	return segs, nil
}

// winDumpBitmap builds segments from a DumpType 5 dump: the summary header
// at page two holds HeaderSize, the page-count bitmap and the data offset.
func winDumpBitmap(f io.ReaderAt, size int64) ([]Segment, error) {
	if size < winDumpSummary+winDumpSumBuf {
		return nil, errors.New("memory: truncated Windows dump summary header")
	}
	sum := make([]byte, winDumpSumBuf)
	if _, err := f.ReadAt(sum, winDumpSummary); err != nil {
		return nil, fmt.Errorf("memory: read Windows dump summary header: %w", err)
	}
	headerSize := int64(binary.LittleEndian.Uint64(sum[winDumpSumHdrSize:]))
	bitmapSize := int64(binary.LittleEndian.Uint64(sum[winDumpSumBmpSize:]))
	if bitmapSize <= 0 || bitmapSize > 1<<28 {
		return nil, fmt.Errorf("memory: implausible Windows dump bitmap size %d", bitmapSize)
	}
	if bitmapSize%4 != 0 {
		return nil, errors.New("memory: Windows dump bitmap size is not a multiple of 4")
	}
	bitmapAt := int64(winDumpSummary + winDumpSumBuf)
	if headerSize < winDumpSumBuf+bitmapSize || bitmapAt+bitmapSize > size {
		return nil, errors.New("memory: Windows dump bitmap exceeds the summary header")
	}
	dataStart := winDumpSummary + headerSize
	if dataStart > size {
		return nil, errors.New("memory: Windows dump data offset past end of file")
	}
	bitmap := make([]byte, bitmapSize)
	if _, err := f.ReadAt(bitmap, bitmapAt); err != nil {
		return nil, fmt.Errorf("memory: read Windows dump bitmap: %w", err)
	}

	var segs []Segment
	fileOff := dataStart
	runStart := int64(-1) // physical page index of the open run, -1 = none
	runBit := int64(-1)   // last set bit inside the open run
	flush := func(lastBit int64) {
		if runStart < 0 {
			return
		}
		length := (lastBit - runStart + 1) * winDumpPageSize
		physStart := uint64(runStart) * winDumpPageSize
		if fileOff < size {
			l := length
			if fileOff+l > size {
				l = size - fileOff // truncated dump: clamp
			}
			if l > 0 {
				segs = append(segs, Segment{
					Index:     len(segs),
					Offset:    fileOff,
					Length:    l,
					AddrStart: physStart,
					AddrEnd:   physStart + uint64(l),
				})
			}
		}
		fileOff += length // positions follow the declared layout
		runStart = -1
		runBit = -1
	}
	totalBits := int64(len(bitmap)) * 8
	for word := 0; word < len(bitmap)/4; word++ {
		w := binary.LittleEndian.Uint32(bitmap[word*4:])
		base := int64(word) * 32
		if w == 0 {
			flush(base - 1) // run, if open, ended at the previous bit
			continue
		}
		for b := 0; b < 32; b++ {
			bit := base + int64(b)
			if bit >= totalBits {
				break
			}
			if w&(1<<b) != 0 {
				if runStart < 0 {
					runStart = bit
				}
				runBit = bit
			} else {
				flush(runBit)
			}
		}
	}
	flush(totalBits - 1)
	if len(segs) == 0 {
		return nil, errors.New("memory: Windows dump bitmap maps no pages")
	}
	if len(segs) > maxSegments {
		return nil, fmt.Errorf("memory: more than %d Windows dump segments", maxSegments)
	}
	sortSegments(segs)
	return segs, nil
}
