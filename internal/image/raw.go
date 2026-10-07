package image

import (
	"fmt"
	"os"
)

// rawReader serves a plain dump file straight from disk.
type rawReader struct {
	f    *os.File
	size int64
}

func openRaw(path string) (Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("image/raw: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("image/raw: %w", err)
	}
	return &rawReader{f: f, size: st.Size()}, nil
}

func (r *rawReader) Size() int64    { return r.size }
func (r *rawReader) Format() string { return FormatRaw }
func (r *rawReader) Close() error   { return r.f.Close() }
func (r *rawReader) ReadAt(p []byte, off int64) (int, error) {
	return r.f.ReadAt(p, off)
}
