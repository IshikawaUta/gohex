package service

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/core"
	"github.com/IshikawaUta/gohex/internal/memory"
)

// MemoryInfo reports the format, size and address segment map of a memory
// capture or crash dump. The capture is opened read-only and only its parsed
// metadata is returned; the access is recorded in the audit log.
func (a *App) MemoryInfo(path string) (memory.Capture, error) {
	if path == "" {
		return memory.Capture{}, errors.New("service: memory: empty path")
	}
	abs := absPath(path)
	mc, err := memory.Open(abs)
	if err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionOpen,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "memory", "error": err.Error()},
		})
		return memory.Capture{}, err
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionOpen,
		Target: abs,
		Result: audit.ResultOK,
		Detail: map[string]string{
			"op":       "memory",
			"format":   mc.Format,
			"segments": strconv.Itoa(len(mc.Segments)),
			"mode":     "read-only",
		},
	})
	return mc, nil
}

// MemoryLocate maps an address inside the capture onto a file offset so the
// caller can open the covering bytes in the hex view. It re-reads the
// capture's headers only; the access is already covered by the MemoryInfo
// audit record, so no second record is written here.
func (a *App) MemoryLocate(path string, addr int64) (memory.Location, error) {
	if path == "" {
		return memory.Location{}, errors.New("service: memory: empty path")
	}
	mc, err := memory.Open(absPath(path))
	if err != nil {
		return memory.Location{}, err
	}
	return mc.Locate(addr)
}

// MemoryOpen opens a memory capture or crash dump as its own hex document,
// exposing the capture's uncompressed byte space: for compressed captures
// (AVML) each Snappy block is decompressed on demand, and for every format
// the document covers the whole capture (offset 0, size 0 = everything).
// The access is recorded in the audit log.
func (a *App) MemoryOpen(path string, offset, size int64) (DocInfo, error) {
	abs := absPath(path)
	r, err := memory.OpenReader(abs)
	if err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionOpen,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "memory-view", "error": err.Error()},
		})
		return DocInfo{}, err
	}
	if offset < 0 || offset > r.Size() {
		r.Close()
		return DocInfo{}, fmt.Errorf("service: memory offset %d outside %q (%d bytes)", offset, abs, r.Size())
	}
	if size <= 0 || offset+size > r.Size() {
		size = r.Size() - offset
	}
	name := abs
	if offset != 0 || size != r.Size() {
		name = fmt.Sprintf("%s[%d:%d]", filepath.Base(abs), offset, offset+size)
	}
	src := &memorySource{r: r, name: name, base: offset, size: size}
	return a.openContainer(abs, src, map[string]string{
		"op":     "memory-view",
		"format": r.Format(),
		"offset": fmt.Sprintf("%d", offset),
	})
}

// memorySource exposes a byte range of a capture's uncompressed view as a
// core document source.
type memorySource struct {
	r    *memory.Reader
	name string
	base int64
	size int64
}

func (s *memorySource) Name() string { return s.name }
func (s *memorySource) Size() int64  { return s.size }
func (s *memorySource) Close() error { return s.r.Close() }

func (s *memorySource) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, core.ErrNegativeOffset
	}
	if off >= s.size {
		return 0, io.EOF
	}
	if max := s.size - off; int64(len(p)) > max {
		p = p[:max]
	}
	n, err := s.r.ReadAt(p, s.base+off)
	if err == io.EOF && n > 0 {
		err = nil // short tail read inside the range is not an error
	}
	return n, err
}
