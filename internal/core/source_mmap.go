package core

import (
	"fmt"
	"io"
	"os"

	"github.com/edsrzf/mmap-go"
)

// mappedSource serves a file through a read-only memory mapping. Reads are
// plain slice copies with no syscalls, which keeps the hex grid responsive on
// multi-gigabyte evidence images.
type mappedSource struct {
	data mmap.MMap
	f    *os.File
	name string
}

// openMapped maps path read-only. It is best-effort: callers fall back to a
// FileSource whenever an error is returned (e.g. filesystems without mmap
// support, or VM overcommit restrictions).
func openMapped(path string, size int64) (Source, error) {
	if size <= 0 {
		return nil, fmt.Errorf("core: cannot map empty file %q", path)
	}
	f, err := os.Open(path) //nolint:gosec // read-only mapping of user-selected evidence
	if err != nil {
		return nil, err
	}
	// MapRegion maps only the requested length, avoiding a huge mapping when
	// the file is sparse at the end.
	data, err := mmap.MapRegion(f, int(size), mmap.RDONLY, 0, 0) //nolint:gosec // size bounded by caller limit
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("core: mmap %q: %w", path, err)
	}
	return &mappedSource{data: data, f: f, name: path}, nil
}

// Name implements Source.
func (m *mappedSource) Name() string { return m.name }

// Size implements Source.
func (m *mappedSource) Size() int64 { return int64(len(m.data)) }

// ReadAt implements Source and io.ReaderAt.
func (m *mappedSource) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, ErrNegativeOffset
	}
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// Close unmaps the region and closes the backing file handle.
func (m *mappedSource) Close() error {
	err1 := m.data.Unmap()
	err2 := m.f.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
