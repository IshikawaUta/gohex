package image

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// EWF (Expert Witness Compression Format) segment layout constants.
const (
	ewfSignature    = "EVF\x09\r\n\xff\x00" // E01 segment file signature
	ewfSignatureL01 = "LVF\x09\r\n\xff\x00" // L01 segment file signature
	ewfSignatureMV  = "MVF\x09\r\n\xff\x00" // observed L01 signature variant
	ewfHeaderSize   = 13
	ewfDescSize     = 76 // section descriptor
	ewfTableHdr     = 24 // table section header
	ewfGeomSize     = 24 // leading bytes of the volume section payload
	ewfCompressMSB  = uint32(0x80000000)
)

// ewfSigClass maps a segment signature onto its family so mixed E01/L01 sets
// are rejected: "evf" for E01, "lvf" for L01 (both LVF and MVF spellings).
func ewfSigClass(sig string) string {
	switch sig {
	case ewfSignature:
		return "evf"
	case ewfSignatureL01, ewfSignatureMV:
		return "lvf"
	}
	return ""
}

// ewfIsSegmentName reports whether base (a file name, not a path) uses the
// fixed three-character E01/EAA/L01/... segment extension.
func ewfIsSegmentName(base string) bool {
	ext := strings.TrimPrefix(filepath.Ext(base), ".")
	if len(ext) != 3 {
		return false
	}
	c := ext[0]
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

// ewfSiblingSegments lists every sibling segment file of path in
// lexicographic order, which for fixed-width segment names is also numeric
// order (E01..E99, EAA..ZZZ, L01..L99, ...). It returns nil when path does
// not use segment naming.
func ewfSiblingSegments(path string) []string {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	if !ewfIsSegmentName(base) {
		return nil
	}
	wild := ".[A-Z]??"
	if ext := strings.TrimPrefix(filepath.Ext(base), "."); ext[0] >= 'a' && ext[0] <= 'z' {
		wild = ".[a-z]??"
	}
	matches, err := filepath.Glob(filepath.Join(dir, base[:len(base)-4]+wild))
	if err != nil || len(matches) == 0 {
		return nil
	}
	sort.Strings(matches)
	for _, m := range matches {
		if filepath.Clean(m) == filepath.Clean(path) {
			return matches
		}
	}
	// The glob can miss the exact spelling of path (odd case mixes); keep it.
	matches = append(matches, path)
	sort.Strings(matches)
	return matches
}

// ewfFileHeader is the decoded 13-byte segment file header.
type ewfFileHeader struct {
	class   string // "evf" for E01, "lvf" for L01
	claim   int    // segment number, little-endian reading
	claimBE int    // segment number, big-endian reading
}

// ewfReadFileHeader reads and validates the segment file header. Validation
// order matters: signature, fields marker, trailing marker, and only then the
// segment number, which callers compare against the expected position.
func ewfReadFileHeader(f io.ReaderAt) (ewfFileHeader, error) {
	var h ewfFileHeader
	hdr := make([]byte, ewfHeaderSize)
	if err := readAtFull(f, hdr, 0); err != nil {
		return h, fmt.Errorf("read segment header: %w", err)
	}
	h.class = ewfSigClass(string(hdr[:8]))
	if h.class == "" {
		return h, errors.New("bad segment signature")
	}
	if hdr[8] != 0x01 {
		return h, fmt.Errorf("unexpected fields marker %#x", hdr[8])
	}
	if hdr[11] != 0x00 || hdr[12] != 0x00 {
		return h, errors.New("trailing fields marker must be 0")
	}
	h.claim = int(binary.LittleEndian.Uint16(hdr[9:11]))
	h.claimBE = int(binary.BigEndian.Uint16(hdr[9:11]))
	return h, nil
}

// ewfChunk locates one chunk of media data inside its segment file.
type ewfChunk struct {
	seg        int   // index into ewfReader.segs
	off        int64 // file offset of the stored chunk
	end        int64 // end offset of the stored chunk
	compressed bool
}

// ewfSegment is one opened file of a (possibly multi-part) EWF set.
type ewfSegment struct {
	f         *os.File
	fileSize  int64
	term      string // terminator section: "done", "next" or "incomplete"
	secBig    bool   // section descriptor byte order
	dataStart int64  // start of the section holding this segment's chunks
	dataEnd   int64  // end of that section
}

// ewfReader reads a multi-segment EWF (.E01) or logical (.L01) image
// natively. Segments are discovered by naming convention next to the opened
// file; nothing is ever written to them.
//
// Byte order is not uniform across the EWF family: section descriptor offsets,
// volume geometry and table entries are each auto-detected from on-disk
// plausibility instead of assumed, because both encodings occur in the wild.
// Chunks are numbered sequentially across segments: segment k holds the
// chunks appended after segment k-1's table.
type ewfReader struct {
	segs      []ewfSegment
	sigClass  string // signature family of the first segment
	format    string // FormatEWF or FormatL01
	size      int64  // virtual size of the imaged medium
	chunkSize int64  // bytes per sector * sectors per chunk
	chunks    []ewfChunk

	mu       sync.Mutex
	cacheIdx int
	cache    []byte
}

func openEWF(path string) (Reader, error) {
	e := &ewfReader{cacheIdx: -1}
	if err := e.parseFrom(path); err != nil {
		e.Close()
		return nil, err
	}
	return e, nil
}

// parseFrom opens path and every sibling segment it needs, then reads their
// section chains into e.
func (e *ewfReader) parseFrom(path string) error {
	base := filepath.Base(path)
	probe, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("image/ewf: %w", err)
	}
	hdr, herr := ewfReadFileHeader(probe)
	probe.Close()
	if herr != nil {
		return fmt.Errorf("image/ewf: %s: %v", base, herr)
	}

	notFirst := hdr.claim >= 2 && hdr.claimBE >= 2
	var set []string
	if ewfIsSegmentName(base) {
		if set = ewfSiblingSegments(path); len(set) == 0 {
			set = []string{path}
		}
	} else if notFirst {
		return fmt.Errorf("image/ewf: %s is not an E01/L01 segment naming", base)
	} else {
		set = []string{path}
	}

	// Always walk from the first segment of the set: opening a middle
	// segment transparently reads its predecessors, so the chunk numbering
	// and the volume geometry come out right.
	for i := 0; i < len(set); i++ {
		seg, term, err := e.parseSegment(set[i], i+1)
		if err != nil {
			return err
		}
		e.segs = append(e.segs, *seg)
		switch term {
		case "next":
			if i+1 >= len(set) {
				return fmt.Errorf("image/ewf: %s: missing continuation", filepath.Base(set[i]))
			}
		default: // "done" or "incomplete"
			if i+1 < len(set) {
				return fmt.Errorf("image/ewf: %s marks the set complete but %s exists",
					filepath.Base(set[i]), filepath.Base(set[i+1]))
			}
		}
		if term != "next" {
			break
		}
	}

	if e.size <= 0 {
		return fmt.Errorf("image/ewf: implausible media size %d", e.size)
	}
	want := (e.size + e.chunkSize - 1) / e.chunkSize
	if int64(len(e.chunks)) < want {
		return fmt.Errorf("image/ewf: %d chunks but the media needs %d", len(e.chunks), want)
	}
	return nil
}

// parseSegment opens one segment file and reads its section chain, appending
// its chunks to e. pos is the 1-based position of the segment in the set.
func (e *ewfReader) parseSegment(path string, pos int) (*ewfSegment, string, error) {
	base := filepath.Base(path)
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("image/ewf: %w", err)
	}
	fail := func(err error) (*ewfSegment, string, error) {
		f.Close()
		return nil, "", err
	}
	wrap := func(err error) error { return fmt.Errorf("image/ewf: %s: %v", base, err) }

	st, err := f.Stat()
	if err != nil {
		return fail(wrap(err))
	}
	hdr, err := ewfReadFileHeader(f)
	if err != nil {
		return fail(wrap(err))
	}
	if pos == 1 {
		e.sigClass = hdr.class
		if hdr.class == "evf" {
			e.format = FormatEWF
		} else {
			e.format = FormatL01
		}
	} else if hdr.class != e.sigClass {
		return fail(wrap(errors.New("different signature")))
	}
	// LE is the primary reading of the segment number, BE covers writers
	// that store it big-endian, and 0/0 means the field was left unspecified.
	if hdr.claim != pos && hdr.claimBE != pos && (hdr.claim != 0 || hdr.claimBE != 0) {
		msg := fmt.Sprintf("segment number mismatch: claim %d, expected %d", hdr.claim, pos)
		if hdr.claim > pos {
			msg += " (is an earlier segment missing?)"
		}
		return fail(wrap(errors.New(msg)))
	}

	seg := &ewfSegment{f: f, fileSize: st.Size()}
	sections, err := seg.walk()
	if err != nil {
		return fail(wrap(err))
	}

	// The volume section carries the media geometry; segment 1 must have it,
	// later segments only parse it when the geometry is still unknown.
	volume := ewfFirstOf(sections, "volume", "disk")
	if pos == 1 && volume == nil {
		return fail(wrap(errors.New("no volume section")))
	}
	if volume != nil && e.size <= 0 {
		if err := e.parseVolume(seg, volume); err != nil {
			return fail(wrap(err))
		}
	}

	term := ""
	for i := range sections {
		s := &sections[i]
		switch s.typ {
		case "sectors":
			// Only "sectors" holds chunk payloads; "data" is a metadata
			// mirror of the volume section.
			if s.size >= ewfDescSize && s.pos+s.size <= seg.fileSize {
				seg.dataStart, seg.dataEnd = s.pos+ewfDescSize, s.pos+s.size
			}
		case "table":
			if err := e.parseTable(seg, s, len(e.segs)); err != nil {
				return fail(wrap(err))
			}
		case "done", "next", "incomplete":
			term = s.typ
		}
	}
	if seg.dataStart == 0 || seg.dataEnd <= seg.dataStart || seg.dataEnd > seg.fileSize {
		seg.dataStart, seg.dataEnd = ewfHeaderSize, seg.fileSize
	}
	return seg, term, nil
}

// ewfSection is one parsed section descriptor.
type ewfSection struct {
	typ  string
	pos  int64
	size int64
}

func dec32(b []byte, big bool) uint32 {
	if big {
		return binary.BigEndian.Uint32(b)
	}
	return binary.LittleEndian.Uint32(b)
}

func dec64(b []byte, big bool) uint64 {
	if big {
		return binary.BigEndian.Uint64(b)
	}
	return binary.LittleEndian.Uint64(b)
}

func ewfFirstOf(sections []ewfSection, types ...string) *ewfSection {
	for i := range sections {
		for _, t := range types {
			if sections[i].typ == t {
				return &sections[i]
			}
		}
	}
	return nil
}

// walk collects every section descriptor by following the "next" chain.
func (s *ewfSegment) walk() ([]ewfSection, error) {
	desc := make([]byte, ewfDescSize)
	pos := int64(ewfHeaderSize)
	if err := readAtFull(s.f, desc, pos); err != nil {
		return nil, fmt.Errorf("read first section descriptor: %w", err)
	}
	// Decide the descriptor byte order once: of the two readings of an 8-byte
	// file offset, only one can plausibly point past the segment header.
	s.secBig = ewfSanePos(dec64(desc[16:24], true), pos, s.fileSize) ||
		!ewfSanePos(dec64(desc[16:24], false), pos, s.fileSize)

	var out []ewfSection
	for i := 0; i < 4096; i++ {
		if pos+ewfDescSize > s.fileSize {
			return nil, fmt.Errorf("truncated section descriptor at %d", pos)
		}
		if err := readAtFull(s.f, desc, pos); err != nil {
			return nil, fmt.Errorf("read section descriptor: %w", err)
		}
		typ := strings.TrimRight(string(desc[:16]), "\x00")
		next := int64(dec64(desc[16:24], s.secBig))
		size := int64(dec64(desc[24:32], s.secBig))
		out = append(out, ewfSection{typ: typ, pos: pos, size: size})

		switch typ {
		case "done", "next", "incomplete":
			return out, nil
		}
		if next <= pos || next > s.fileSize {
			return nil, fmt.Errorf("section %q at %d has bad next offset %d", typ, pos, next)
		}
		pos = next
	}
	return nil, errors.New("section chain too long")
}

func ewfSanePos(v uint64, pos, fileSize int64) bool {
	return v >= uint64(ewfHeaderSize) && v <= uint64(fileSize) && int64(v) > pos
}

// parseVolume reads geometry from the volume/disk section payload.
func (e *ewfReader) parseVolume(seg *ewfSegment, s *ewfSection) error {
	if s.pos+ewfDescSize+ewfGeomSize > seg.fileSize {
		return errors.New("volume section beyond end of file")
	}
	payload := make([]byte, ewfGeomSize)
	if err := readAtFull(seg.f, payload, s.pos+ewfDescSize); err != nil {
		return fmt.Errorf("read volume section: %w", err)
	}
	// Bytes per sector, sectors per chunk and sector count sit at the same
	// offsets in both the 94-byte (ASR) and 1052-byte (EnCase) variants, but
	// their byte order has varied: validate both readings instead of guessing.
	for _, big := range []bool{false, true} {
		bps := dec32(payload[12:16], big)
		spc := dec32(payload[8:12], big)
		sectors := dec64(payload[16:24], big)
		if bps < 128 || bps > 4096 || bps&(bps-1) != 0 {
			continue
		}
		if spc == 0 || spc > 65536 || spc&(spc-1) != 0 {
			continue
		}
		if sectors == 0 || sectors > 1<<48 {
			continue
		}
		e.chunkSize = int64(bps) * int64(spc)
		e.size = int64(sectors) * int64(bps)
		return nil
	}
	return errors.New("unrecognisable volume geometry")
}

// parseTable decodes one segment's table section's chunk index.
func (e *ewfReader) parseTable(seg *ewfSegment, s *ewfSection, segIdx int) error {
	if s.pos+ewfDescSize+ewfTableHdr > seg.fileSize {
		return errors.New("table section beyond end of file")
	}
	hdr := make([]byte, ewfTableHdr)
	if err := readAtFull(seg.f, hdr, s.pos+ewfDescSize); err != nil {
		return fmt.Errorf("read table header: %w", err)
	}
	count := int64(dec32(hdr[0:4], seg.secBig))
	tableBase := int64(dec64(hdr[8:16], seg.secBig))
	if count <= 0 || count > 1<<20 {
		return fmt.Errorf("implausible chunk count %d", count)
	}
	entryOff := s.pos + ewfDescSize + ewfTableHdr
	if entryOff+count*4 > seg.fileSize {
		return errors.New("table entries beyond end of file")
	}
	entries := make([]byte, count*4)
	if err := readAtFull(seg.f, entries, entryOff); err != nil {
		return fmt.Errorf("read table entries: %w", err)
	}

	// The data range holding this segment's chunks: normally the "sectors"
	// section before it, or the table section itself for SMART/EnCase 1
	// layouts that embed chunks in the table.
	ds, de := seg.dataStart, seg.dataEnd
	if ds == 0 || de <= ds {
		ds, de = s.pos+ewfDescSize, s.pos+s.size
		if de <= ds {
			de = seg.fileSize
		}
	}
	// Pick the entry byte order: entries must be strictly ascending, start
	// inside the data section, and leave room for one final chunk.
	beOK := ewfEntriesPlausible(entries, count, true, ds, de, e.chunkSize, tableBase)
	leOK := ewfEntriesPlausible(entries, count, false, ds, de, e.chunkSize, tableBase)
	var entryBig bool
	switch {
	case beOK && !leOK:
		entryBig = true
	case leOK && !beOK:
		entryBig = false
	case beOK && leOK:
		entryBig = seg.secBig // ambiguous: follow the descriptor's byte order
	default:
		return errors.New("cannot resolve table entry byte order")
	}

	offs := make([]int64, count)
	comp := make([]bool, count)
	for i := int64(0); i < count; i++ {
		v := dec32(entries[i*4:], entryBig)
		offs[i] = int64(v&^ewfCompressMSB) + tableBase
		comp[i] = v&ewfCompressMSB != 0
	}
	// Chunks are written back to back: the next chunk's offset bounds this
	// one; only the segment's final chunk is bounded by the data section.
	for i := int64(0); i < count; i++ {
		end := de
		if i+1 < count {
			end = offs[i+1]
		}
		e.chunks = append(e.chunks, ewfChunk{
			seg:        segIdx,
			off:        offs[i],
			end:        end,
			compressed: comp[i],
		})
	}
	return nil
}

func ewfEntriesPlausible(entries []byte, count int64, big bool, dataStart, dataEnd, chunkSize, tableBase int64) bool {
	if dataEnd <= dataStart || chunkSize <= 0 {
		return false
	}
	prev := int64(-1)
	for i := int64(0); i < count; i++ {
		off := int64(dec32(entries[i*4:], big)&^ewfCompressMSB) + tableBase
		if off <= prev || off < dataStart || off >= dataEnd {
			return false
		}
		prev = off
	}
	return dataEnd-prev <= 2*chunkSize
}

func (e *ewfReader) Size() int64    { return e.size }
func (e *ewfReader) Format() string { return e.format }

// Close releases every segment file handle.
func (e *ewfReader) Close() error {
	var err error
	for i := range e.segs {
		if cerr := e.segs[i].f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// chunk returns the uncompressed payload of chunk i.
func (e *ewfReader) chunk(i int) ([]byte, error) {
	e.mu.Lock()
	if e.cacheIdx == i && e.cache != nil {
		c := e.cache
		e.mu.Unlock()
		return c, nil
	}
	e.mu.Unlock()

	need := e.chunkSize
	if last := e.size - int64(i)*e.chunkSize; last < need {
		need = last
	}
	if need <= 0 {
		return nil, io.EOF
	}
	c := e.chunks[i]
	seg := &e.segs[c.seg]
	ln := c.end - c.off
	if c.off < 0 || c.off >= seg.fileSize || ln <= 0 || c.end > seg.fileSize {
		return nil, fmt.Errorf("image/ewf: chunk %d has implausible bounds [%d,%d]", i, c.off, c.end)
	}
	raw := make([]byte, ln)
	if err := readAtFull(seg.f, raw, c.off); err != nil {
		return nil, fmt.Errorf("image/ewf: read chunk %d: %w", i, err)
	}

	var payload []byte
	if c.compressed {
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("image/ewf: chunk %d: %w", i, err)
		}
		payload, err = io.ReadAll(io.LimitReader(zr, e.chunkSize+1))
		zr.Close()
		if err != nil {
			return nil, fmt.Errorf("image/ewf: decompress chunk %d: %w", i, err)
		}
		if int64(len(payload)) > e.chunkSize {
			return nil, fmt.Errorf("image/ewf: chunk %d inflates past the chunk size", i)
		}
	} else {
		// Uncompressed chunks carry a trailing 4-byte Adler-32 checksum.
		payload = raw
		if int64(len(raw)) >= need+4 {
			payload = raw[:len(raw)-4]
		}
	}
	if int64(len(payload)) < need {
		return nil, fmt.Errorf("image/ewf: chunk %d is short (%d < %d)", i, len(payload), need)
	}
	payload = payload[:need]

	e.mu.Lock()
	e.cacheIdx, e.cache = i, payload
	e.mu.Unlock()
	return payload, nil
}

func (e *ewfReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if off >= e.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > e.size-off {
		want = int(e.size - off)
	}
	filled := 0
	for filled < want {
		abs := off + int64(filled)
		idx := int(abs / e.chunkSize)
		inChunk := abs % e.chunkSize
		data, err := e.chunk(idx)
		if err != nil {
			return filled, err
		}
		n := copy(p[filled:want], data[inChunk:])
		if n == 0 {
			return filled, io.EOF
		}
		filled += n
	}
	if filled < len(p) {
		return filled, io.EOF
	}
	return filled, nil
}
