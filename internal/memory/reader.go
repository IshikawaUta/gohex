package memory

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
)

// Reader is an uncompressed virtual view of a capture: the segment
// payloads concatenated in address order (dense offsets 0..Size-1).
// Uncompressed formats read straight from the file; AVML captures
// decompress each Snappy block on demand and cache the segment being
// read. Reader implements the core.Source shape (Name/Size/ReadAt/Close)
// without importing core, and is safe for concurrent use.
type Reader struct {
	cap   Capture
	f     *os.File
	dense []int64 // dense[i] = virtual start of segment i; len = n+1, last = total size

	mu     sync.Mutex
	cacheI int // cached segment index, -1 when empty
	cache  []byte
}

// OpenReader parses the capture at path and opens its uncompressed
// virtual view. The caller must Close the reader.
func OpenReader(path string) (*Reader, error) {
	cap, err := Open(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("memory: %w", err)
	}
	dense := make([]int64, len(cap.Segments)+1)
	for i, s := range cap.Segments {
		dense[i+1] = dense[i] + s.Length
	}
	return &Reader{cap: cap, f: f, dense: dense, cacheI: -1}, nil
}

// Name returns the capture path.
func (r *Reader) Name() string { return r.cap.Path }

// Size returns the total uncompressed bytes across all segments.
func (r *Reader) Size() int64 { return r.dense[len(r.dense)-1] }

// Format returns the detected capture format.
func (r *Reader) Format() string { return r.cap.Format }

// Capture returns a copy of the parsed capture metadata (segment map,
// details, bugcheck). The Reader keeps its own copy for reads.
func (r *Reader) Capture() Capture { return r.cap }

// Locate maps an address inside the capture onto a file offset using
// the reader's parsed segment map.
func (r *Reader) Locate(addr int64) (Location, error) { return r.cap.Locate(addr) }

// Close releases the underlying file.
func (r *Reader) Close() error { return r.f.Close() }

// ReadAt reads len(p) uncompressed bytes at virtual offset off. It
// follows io.ReaderAt semantics.
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("memory: negative read offset")
	}
	if off >= r.Size() {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) {
		cur := off + int64(n)
		if cur >= r.Size() {
			return n, io.EOF
		}
		i := sort.Search(len(r.cap.Segments), func(i int) bool {
			return r.dense[i+1] > cur
		})
		rel := cur - r.dense[i]
		chunk := r.cap.Segments[i].Length - rel
		if max := int64(len(p) - n); chunk > max {
			chunk = max
		}
		if err := r.readSegment(i, p[n:n+int(chunk)], rel); err != nil {
			return n, err
		}
		n += int(chunk)
	}
	return n, nil
}

// readSegment fills p from segment i at relative offset rel, decompressing
// and caching the segment when the capture is compressed.
func (r *Reader) readSegment(i int, p []byte, rel int64) error {
	seg := r.cap.Segments[i]
	if !r.cap.Compressed {
		_, err := r.f.ReadAt(p, seg.Offset+rel)
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cacheI != i {
		b := r.cap.blocks[i]
		buf := make([]byte, b.compLen)
		if _, err := r.f.ReadAt(buf, b.fileOff); err != nil {
			return fmt.Errorf("memory: read AVML block %d: %w", i, err)
		}
		raw, err := decodeSnappyFrames(buf, seg.Length)
		if err != nil {
			return fmt.Errorf("memory: decompress AVML block %d: %w", i, err)
		}
		r.cache, r.cacheI = raw, i
	}
	copy(p, r.cache[rel:rel+int64(len(p))])
	return nil
}
