// Package core provides the low-level byte-source abstraction shared by every
// GoHex engine: random-access read-only sources (plain file streams and
// memory maps), bounded window reads that are safe for files of any size, and
// offset parsing utilities used by the GUI, CLI and service layers.
package core

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrOutOfBounds is returned when a read starts or extends beyond the end of
// the underlying source.
var ErrOutOfBounds = errors.New("core: offset out of bounds")

// ErrNegativeOffset is returned for negative offsets.
var ErrNegativeOffset = errors.New("core: negative offset")

// MaxWindow is the largest single window read allowed by ReadWindow. It bounds
// memory usage regardless of caller arguments (GUI panels request far less).
const MaxWindow = 64 << 20 // 64 MiB

// Source is a read-only, random-access byte source. Implementations must be
// safe for concurrent use by multiple readers, and must work for sources
// larger than 4 GiB (offsets are int64).
type Source interface {
	// Name returns a human-readable identifier (usually the file path).
	Name() string
	// Size returns the total number of bytes available.
	Size() int64
	// ReadAt reads len(p) bytes at offset off. It follows io.ReaderAt: it may
	// return fewer bytes with a nil error only when the source ends, and must
	// return io.EOF when off is at or past the end.
	ReadAt(p []byte, off int64) (int, error)
	// Close releases underlying resources (file handle, mapping).
	Close() error
}

// FileSource reads a file through os.File. It is the portable fallback used
// whenever memory mapping is unavailable or disabled.
type FileSource struct {
	f    *os.File
	name string
	size int64
}

// OpenFile opens path as a read-only Source. The file is opened with
// O_RDONLY: GoHex never opens files for writing through a Source.
func OpenFile(path string) (*FileSource, error) {
	f, err := os.Open(path) //nolint:gosec // path is user-selected evidence, read-only by design
	if err != nil {
		return nil, fmt.Errorf("core: open %q: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("core: stat %q: %w", path, err)
	}
	if st.IsDir() {
		f.Close()
		return nil, fmt.Errorf("core: %q is a directory", path)
	}
	return &FileSource{f: f, name: path, size: st.Size()}, nil
}

// Name implements Source.
func (s *FileSource) Name() string { return s.name }

// Size implements Source.
func (s *FileSource) Size() int64 { return s.size }

// ReadAt implements Source and io.ReaderAt.
func (s *FileSource) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, ErrNegativeOffset
	}
	if off >= s.size {
		return 0, io.EOF
	}
	return s.f.ReadAt(p, off)
}

// Close implements Source.
func (s *FileSource) Close() error { return s.f.Close() }

// Open opens path preferring a read-only memory map and falling back to a
// plain file stream when mapping is not possible (unsupported filesystem,
// resource limits, or a source larger than mmapLimitBytes).
//
// mmapLimitBytes caps mapped size to avoid exhausting address space on
// pathological inputs; pass 0 for the default (32 GiB).
func Open(path string, mmapLimitBytes int64) (Source, error) {
	fs, err := OpenFile(path)
	if err != nil {
		return nil, err
	}
	if mmapLimitBytes <= 0 {
		mmapLimitBytes = 32 << 30
	}
	if fs.Size() > mmapLimitBytes {
		return fs, nil
	}
	ms, err := openMapped(path, fs.Size())
	if err != nil {
		return fs, nil // keep stream fallback
	}
	return ms, nil
}

// ReadWindow reads up to n bytes starting at off, clamping the read to the
// source bounds. It returns a slice shorter than n when the end of the source
// is reached, and an empty slice with ErrOutOfBounds when off is beyond the
// end. n is capped at MaxWindow.
func ReadWindow(src Source, off int64, n int) ([]byte, error) {
	if off < 0 {
		return nil, ErrNegativeOffset
	}
	if n <= 0 {
		return nil, nil
	}
	if n > MaxWindow {
		n = MaxWindow
	}
	size := src.Size()
	if off >= size {
		return nil, ErrOutOfBounds
	}
	if int64(n) > size-off {
		n = int(size - off)
	}
	buf := make([]byte, n)
	got, err := src.ReadAt(buf, off)
	if got > 0 && (err == nil || errors.Is(err, io.EOF)) {
		return buf[:got], nil
	}
	if err == nil {
		err = io.EOF
	}
	if errors.Is(err, io.EOF) && got > 0 {
		return buf[:got], nil
	}
	return nil, fmt.Errorf("core: read window at %#x: %w", off, err)
}
