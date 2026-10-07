package image

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// EWF (Expert Witness Compression Format) segment layout constants.
const (
	ewfSignature   = "EVF\x09\r\n\xff\x00" // .E01 segment file signature
	ewfHeaderSize  = 13
	ewfDescSize    = 76 // section descriptor
	ewfTableHdr    = 24 // table section header
	ewfGeomSize    = 24 // leading bytes of the volume section payload
	ewfCompressMSB = uint32(0x80000000)
)

// ewfChunk locates one chunk of media data inside the segment file.
type ewfChunk struct {
	off        int64 // file offset of the stored chunk
	compressed bool
}

// ewfReader reads a single-segment EWF (.E01) image natively.
//
// Byte order is not uniform across the EWF family: section descriptor offsets,
// volume geometry and table entries are each auto-detected from on-disk
// plausibility instead of assumed, because both encodings occur in the wild.
type ewfReader struct {
	f         *os.File
	fileSize  int64
	size      int64 // virtual size of the imaged medium
	chunkSize int64 // bytes per sector * sectors per chunk
	chunks    []ewfChunk
	dataStart int64 // start of the section holding this table's chunks
	dataEnd   int64 // end of that section
	secBig    bool  // section descriptor byte order
	entryBig  bool  // table entry byte order

	mu       sync.Mutex
	cacheIdx int
	cache    []byte
}

func openEWF(path string) (Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("image/ewf: %w", err)
	}
	fail := func(err error) (Reader, error) {
		f.Close()
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		return fail(fmt.Errorf("image/ewf: %w", err))
	}
	e := &ewfReader{f: f, fileSize: st.Size(), cacheIdx: -1}
	if err := e.parse(); err != nil {
		return fail(err)
	}
	return e, nil
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

func (e *ewfReader) parse() error {
	hdr := make([]byte, ewfHeaderSize)
	if err := readAtFull(e.f, hdr, 0); err != nil {
		return fmt.Errorf("image/ewf: read segment header: %w", err)
	}
	if string(hdr[:8]) != ewfSignature {
		return fmt.Errorf("image/ewf: bad segment signature")
	}
	if hdr[8] != 0x01 {
		return fmt.Errorf("image/ewf: unexpected fields marker %#x", hdr[8])
	}
	if hdr[11] != 0x00 || hdr[12] != 0x00 {
		return fmt.Errorf("image/ewf: trailing fields marker must be 0")
	}

	sections, err := e.walk()
	if err != nil {
		return err
	}

	// Geometry must be known before tables are scored for byte order.
	volume := e.firstOf(sections, "volume", "disk")
	if volume == nil {
		return fmt.Errorf("image/ewf: no volume section")
	}
	if err := e.parseVolume(volume); err != nil {
		return err
	}

	for i := range sections {
		s := &sections[i]
		switch s.typ {
		case "sectors":
			// Only "sectors" holds chunk payloads; "data" is a metadata
			// mirror of the volume section.
			if s.size >= ewfDescSize && s.pos+s.size <= e.fileSize {
				e.dataStart, e.dataEnd = s.pos+ewfDescSize, s.pos+s.size
			}
		case "table":
			if err := e.parseTable(s); err != nil {
				return err
			}
		}
	}

	if e.size <= 0 {
		return fmt.Errorf("image/ewf: implausible media size %d", e.size)
	}
	want := (e.size + e.chunkSize - 1) / e.chunkSize
	if int64(len(e.chunks)) < want {
		return fmt.Errorf("image/ewf: %d chunks but the media needs %d", len(e.chunks), want)
	}
	if e.dataStart == 0 || e.dataEnd <= e.dataStart || e.dataEnd > e.fileSize {
		e.dataStart, e.dataEnd = ewfHeaderSize, e.fileSize
	}
	return nil
}

func (e *ewfReader) firstOf(sections []ewfSection, types ...string) *ewfSection {
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
func (e *ewfReader) walk() ([]ewfSection, error) {
	desc := make([]byte, ewfDescSize)
	pos := int64(ewfHeaderSize)
	if err := readAtFull(e.f, desc, pos); err != nil {
		return nil, fmt.Errorf("image/ewf: read first section descriptor: %w", err)
	}
	// Decide the descriptor byte order once: of the two readings of an 8-byte
	// file offset, only one can plausibly point past the segment header.
	e.secBig = ewfSanePos(dec64(desc[16:24], true), pos, e.fileSize) ||
		!ewfSanePos(dec64(desc[16:24], false), pos, e.fileSize)

	var out []ewfSection
	for i := 0; i < 4096; i++ {
		if pos+ewfDescSize > e.fileSize {
			return nil, fmt.Errorf("image/ewf: truncated section descriptor at %d", pos)
		}
		if err := readAtFull(e.f, desc, pos); err != nil {
			return nil, fmt.Errorf("image/ewf: read section descriptor: %w", err)
		}
		typ := strings.TrimRight(string(desc[:16]), "\x00")
		next := int64(dec64(desc[16:24], e.secBig))
		size := int64(dec64(desc[24:32], e.secBig))
		out = append(out, ewfSection{typ: typ, pos: pos, size: size})

		switch typ {
		case "done", "next", "incomplete":
			return out, nil
		}
		if next <= pos || next > e.fileSize {
			return nil, fmt.Errorf("image/ewf: section %q at %d has bad next offset %d", typ, pos, next)
		}
		pos = next
	}
	return nil, fmt.Errorf("image/ewf: section chain too long")
}

func ewfSanePos(v uint64, pos, fileSize int64) bool {
	return v >= uint64(ewfHeaderSize) && v <= uint64(fileSize) && int64(v) > pos
}

// parseVolume reads geometry from the volume/disk section payload.
func (e *ewfReader) parseVolume(s *ewfSection) error {
	if s.pos+ewfDescSize+ewfGeomSize > e.fileSize {
		return fmt.Errorf("image/ewf: volume section beyond end of file")
	}
	payload := make([]byte, ewfGeomSize)
	if err := readAtFull(e.f, payload, s.pos+ewfDescSize); err != nil {
		return fmt.Errorf("image/ewf: read volume section: %w", err)
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
	return fmt.Errorf("image/ewf: unrecognisable volume geometry")
}

// parseTable decodes one table section's chunk index.
func (e *ewfReader) parseTable(s *ewfSection) error {
	if s.pos+ewfDescSize+ewfTableHdr > e.fileSize {
		return fmt.Errorf("image/ewf: table section beyond end of file")
	}
	hdr := make([]byte, ewfTableHdr)
	if err := readAtFull(e.f, hdr, s.pos+ewfDescSize); err != nil {
		return fmt.Errorf("image/ewf: read table header: %w", err)
	}
	count := int64(dec32(hdr[0:4], e.secBig))
	tableBase := int64(dec64(hdr[8:16], e.secBig))
	if count <= 0 || count > 1<<20 {
		return fmt.Errorf("image/ewf: implausible chunk count %d", count)
	}
	entryOff := s.pos + ewfDescSize + ewfTableHdr
	if entryOff+count*4 > e.fileSize {
		return fmt.Errorf("image/ewf: table entries beyond end of file")
	}
	entries := make([]byte, count*4)
	if err := readAtFull(e.f, entries, entryOff); err != nil {
		return fmt.Errorf("image/ewf: read table entries: %w", err)
	}

	// The data range holding this table's chunks: normally the "sectors"
	// section before it, or the table section itself for SMART/EnCase 1
	// layouts that embed chunks in the table.
	ds, de := e.dataStart, e.dataEnd
	if ds == 0 || de <= ds {
		ds, de = s.pos+ewfDescSize, s.pos+s.size
		if de <= ds {
			de = e.fileSize
		}
	}
	// Pick the entry byte order: entries must be strictly ascending, start
	// inside the data section, and leave room for one final chunk.
	beOK := ewfEntriesPlausible(entries, count, true, ds, de, e.chunkSize, tableBase)
	leOK := ewfEntriesPlausible(entries, count, false, ds, de, e.chunkSize, tableBase)
	switch {
	case beOK && !leOK:
		e.entryBig = true
	case leOK && !beOK:
		e.entryBig = false
	case beOK && leOK:
		e.entryBig = e.secBig // ambiguous: follow the descriptor's byte order
	default:
		return fmt.Errorf("image/ewf: cannot resolve table entry byte order")
	}

	for i := int64(0); i < count; i++ {
		v := dec32(entries[i*4:], e.entryBig)
		e.chunks = append(e.chunks, ewfChunk{
			off:        int64(v&^ewfCompressMSB) + tableBase,
			compressed: v&ewfCompressMSB != 0,
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
func (e *ewfReader) Format() string { return FormatEWF }
func (e *ewfReader) Close() error   { return e.f.Close() }

// storedLen returns how many bytes chunk i occupies in the segment file.
// Chunks are written back to back, so the next chunk's offset bounds this
// one; only the final chunk is bounded by the end of the data section.
func (e *ewfReader) storedLen(i int) (int64, error) {
	start := e.chunks[i].off
	var end int64
	if i+1 < len(e.chunks) {
		end = e.chunks[i+1].off
	} else {
		end = e.dataEnd
	}
	if start < 0 || start >= e.fileSize || end <= start || end > e.fileSize {
		return 0, fmt.Errorf("image/ewf: chunk %d has implausible bounds [%d,%d]", i, start, end)
	}
	return end - start, nil
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
	ln, err := e.storedLen(i)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, ln)
	if err := readAtFull(e.f, raw, e.chunks[i].off); err != nil {
		return nil, fmt.Errorf("image/ewf: read chunk %d: %w", i, err)
	}

	var payload []byte
	if e.chunks[i].compressed {
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
