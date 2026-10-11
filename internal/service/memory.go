package service

import (
	"errors"
	"fmt"
	"io"
	"os"
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
	if errors.Is(err, io.EOF) && n > 0 {
		err = nil // short tail read inside the range is not an error
	}
	return n, err
}

// MemoryStack performs a best-effort frame-pointer walk of the given
// thread's stack inside a dump and returns the frames, each resolved to
// a module plus offset when the address falls inside one. The access is
// recorded in the audit log.
func (a *App) MemoryStack(path string, threadID uint32) ([]memory.StackFrame, error) {
	if path == "" {
		return nil, errors.New("service: memory: empty path")
	}
	abs := absPath(path)
	mc, err := memory.Open(abs)
	if err != nil {
		return nil, err
	}
	frames, err := mc.WalkStack(abs, threadID)
	if err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionOpen,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "stack-walk", "error": err.Error()},
		})
		return nil, err
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionOpen,
		Target: abs,
		Result: audit.ResultOK,
		Detail: map[string]string{"op": "stack-walk", "thread": strconv.FormatUint(uint64(threadID), 10)},
	})
	return frames, nil
}

// MemoryCompareModules diffs the loaded-module sets of two dumps by
// base+size identity. Both accesses are recorded in the audit log.
func (a *App) MemoryCompareModules(pathA, pathB string) (memory.ModuleDiff, error) {
	if pathA == "" || pathB == "" {
		return memory.ModuleDiff{}, errors.New("service: memory: empty path")
	}
	aA, err := memory.Open(absPath(pathA))
	if err != nil {
		return memory.ModuleDiff{}, err
	}
	aB, err := memory.Open(absPath(pathB))
	if err != nil {
		return memory.ModuleDiff{}, err
	}
	diff := memory.DiffModules(aA.Details, aB.Details)
	_ = a.log.Log(audit.Event{
		Action: audit.ActionOpen,
		Target: absPath(pathA),
		Result: audit.ResultOK,
		Detail: map[string]string{
			"op":     "module-diff",
			"other":  absPath(pathB),
			"common": strconv.Itoa(diff.Common),
		},
	})
	return diff, nil
}

// maxDumpRange bounds a single region extraction (1 GiB).
const maxDumpRange = 1 << 30

// MemoryDumpRange extracts length bytes of the capture's address space
// starting at addr into outPath (read-only source, read-only extraction).
// The export is recorded in the audit log with the byte count.
func (a *App) MemoryDumpRange(path string, addr, length int64, outPath string) (int64, error) {
	if path == "" || outPath == "" {
		return 0, errors.New("service: memory: empty path")
	}
	if length <= 0 || length > maxDumpRange {
		return 0, fmt.Errorf("service: memory: dump length %d outside (0,%d]", length, maxDumpRange)
	}
	abs := absPath(path)
	r, err := memory.OpenReader(abs)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	// Translate the address into the Reader's dense view.
	var dense int64
	covered := false
	c := r.Capture()
	for i := range c.Segments {
		s := &c.Segments[i]
		if uint64(addr) >= s.AddrStart && uint64(addr) < s.AddrEnd {
			dense += int64(uint64(addr) - s.AddrStart)
			covered = true
			break
		}
		dense += s.Length
	}
	if !covered {
		return 0, fmt.Errorf("service: memory: address %#x is not covered by the capture", addr)
	}
	out, err := os.Create(absPath(outPath))
	if err != nil {
		return 0, fmt.Errorf("service: memory: create %s: %w", outPath, err)
	}
	defer out.Close()
	buf := make([]byte, 64<<10)
	var written int64
	for written < length {
		n := int64(len(buf))
		if remaining := length - written; n > remaining {
			n = remaining
		}
		got, err := r.ReadAt(buf[:n], dense+written)
		if got > 0 {
			if _, werr := out.Write(buf[:got]); werr != nil {
				return written, werr
			}
			written += int64(got)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break // capture ended early: export what exists
			}
			if got == 0 {
				return written, err
			}
		}
		if got == 0 {
			break
		}
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionExport,
		Target: abs,
		Result: audit.ResultOK,
		Detail: map[string]string{
			"op":      "memory-extract",
			"addr":    fmt.Sprintf("%#x", addr),
			"want":    strconv.FormatInt(length, 10),
			"written": strconv.FormatInt(written, 10),
			"out":     absPath(outPath),
		},
	})
	return written, nil
}
