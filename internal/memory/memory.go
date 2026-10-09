// Package memory opens memory captures (RAM dumps) read-only and exposes
// their physical-memory segment layout, so callers can map a physical
// address onto a file offset and hand byte ranges to the hex view.
//
// Nothing in this package ever writes to the capture; every parse is
// strictly read-only.
//
// Supported capture formats:
//
//   - lime    LiME v1 range headers with uncompressed payloads (magic "EMiL")
//   - raw     headerless dump, exposed as one segment without an address map
//
// Detection is magic-based (never extension-based), matching internal/image.
package memory

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

// Capture format identifiers returned by Capture.Format.
const (
	FormatLIME = "lime"
	FormatRAW  = "raw"
)

const (
	limeMagic   = "EMiL" // 0x4C694D45 as uint32 little-endian
	limeHeader  = 32     // magic, version, start, end, reserved
	maxSegments = 1 << 16
)

// Segment is one contiguous run of physical memory stored in the capture.
// For mapped segments Length == PhysEnd - PhysStart; PhysEnd is exclusive.
// Captures without an address map (raw) carry Offset/Length only.
type Segment struct {
	Index     int    `json:"index"`
	Offset    int64  `json:"offset"` // byte offset of the payload in the file
	Length    int64  `json:"length"`
	PhysStart uint64 `json:"physStart"`
	PhysEnd   uint64 `json:"physEnd"` // exclusive; 0 when the format carries no map
}

// Capture is the parsed metadata of a memory capture file.
type Capture struct {
	Path     string    `json:"path"`
	Format   string    `json:"format"`
	Size     int64     `json:"size"`
	HasPhys  bool      `json:"hasPhys"` // physical address map available
	Segments []Segment `json:"segments"`
}

// Location is where a physical address lands inside the capture file.
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

	var segs []Segment
	format := FormatRAW
	if isLIME(f, size) {
		format = FormatLIME
		if segs, err = parseLIME(f, size); err != nil {
			return Capture{}, err
		}
	} else {
		segs = []Segment{{Index: 0, Offset: 0, Length: size}}
	}
	return Capture{Path: path, Format: format, Size: size, HasPhys: format == FormatLIME, Segments: segs}, nil
}

// isLIME reports whether the capture starts with the LiME magic.
func isLIME(f io.ReaderAt, size int64) bool {
	if size < int64(len(limeMagic)) {
		return false
	}
	var head [4]byte
	if _, err := f.ReadAt(head[:], 0); err != nil {
		return false
	}
	return string(head[:]) == limeMagic
}

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
			PhysStart: start,
			PhysEnd:   end + 1,
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

// Locate maps a physical address onto a file offset. It fails for captures
// that carry no physical address map (raw dumps) and for addresses the
// capture does not cover.
func (c *Capture) Locate(phys int64) (Location, error) {
	if !c.HasPhys {
		return Location{}, errors.New("memory: capture has no physical address map")
	}
	if phys < 0 {
		return Location{}, errors.New("memory: negative physical address")
	}
	for i := range c.Segments {
		s := &c.Segments[i]
		if uint64(phys) >= s.PhysStart && uint64(phys) < s.PhysEnd {
			return Location{Offset: s.Offset + int64(uint64(phys)-s.PhysStart), Segment: i}, nil
		}
	}
	return Location{}, fmt.Errorf("memory: physical address %#x is not covered by the capture", phys)
}
