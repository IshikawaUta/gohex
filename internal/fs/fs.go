// Package fs provides read-only filesystem readers. A filesystem is opened
// over a byte range (a partition inside a disk image, or a whole
// superfloppy image) and exposes directory listing plus random-access file
// reads. Nothing in this package ever writes to the underlying medium, and
// no platform-specific mount is used: parsing is pure userspace.
//
// Supported filesystems: FAT12/16/32, exFAT, ext2/3/4, NTFS, ISO 9660
// (with Rock Ridge names where present), HFS+/HFSX and APFS (read-only).
// Probing is by on-disk magic only.
package fs

import (
	"errors"
	"fmt"
	"io"
	"time"
)

// Reader is the minimal read interface fs needs; core.Source satisfies it.
type Reader interface {
	Size() int64
	ReadAt(p []byte, off int64) (int, error)
}

// ErrNotFound is returned by List/Stat/ReadAt when the path does not exist.
var ErrNotFound = errors.New("fs: path not found")

// ErrNotDir is returned when a path is used as a directory but is a file.
var ErrNotDir = errors.New("fs: not a directory")

// ErrIsDir is returned when a file is expected but the path is a directory.
var ErrIsDir = errors.New("fs: is a directory")

// Entry describes one directory entry or file node.
type Entry struct {
	// Name is the final path component (no slash).
	Name string `json:"name"`
	// Path is the absolute slash-separated path from the root ("/a/b").
	Path string `json:"path"`
	// Dir reports whether the entry is a directory.
	Dir bool `json:"dir"`
	// Size is the logical file size in bytes (0 for directories).
	Size int64 `json:"size"`
	// Modified is the last modification time (zero when unknown).
	Modified time.Time `json:"modified"`
	// Created is the creation time (zero when unknown).
	Created time.Time `json:"created"`
	// Deleted marks entries that are visibly unlinked (FAT 0xE5) but not
	// yet overwritten. Their names are only best-effort.
	Deleted bool `json:"deleted,omitempty"`
	// Attributes is a free-form flag string for UI display
	// ("hidden", "system", "readonly", ...).
	Attributes []string `json:"attributes,omitempty"`
}

// FS is a read-only filesystem view.
//
// Paths are absolute slash-separated ("/dir/file"). Directory paths may be
// given with or without a trailing slash. Lookups are case-insensitive for
// FAT/exFAT/NTFS and case-sensitive for ext/ISO, mirroring each
// filesystem's own semantics.
type FS interface {
	// Type returns the filesystem identifier: "fat12", "fat16", "fat32",
	// "exfat", "ext2", "ext3", "ext4", "ntfs", "iso9660".
	Type() string
	// Label returns the volume label ("" if none).
	Label() string
	// TotalSize returns the size of the byte range the filesystem covers.
	TotalSize() int64
	// List returns the entries of the directory at path. Unknown paths
	// yield ErrNotFound; non-directories yield ErrNotDir.
	List(path string) ([]Entry, error)
	// Stat returns the entry at path.
	Stat(path string) (Entry, error)
	// ReadAt fills p with file data at path starting at off. It follows
	// io.ReaderAt semantics (io.EOF at/past the end).
	ReadAt(path string, off int64, p []byte) (int, error)
}

// Probe identifies the filesystem living in src[offset:offset+length] and
// returns a reader for it. The byte range stays owned by the caller; fs
// only reads. When length <= 0 the range extends to the end of src.
func Probe(src Reader, offset, length int64) (FS, error) {
	if offset < 0 || offset > src.Size() {
		return nil, fmt.Errorf("fs: partition offset %#x out of range", offset)
	}
	if length <= 0 || offset+length > src.Size() {
		length = src.Size() - offset
	}
	if length < 4096 {
		return nil, fmt.Errorf("fs: range too small (%d bytes)", length)
	}
	r := rangeReader{src: src, off: offset, size: length}

	head := make([]byte, 64<<10)
	if int64(len(head)) > length {
		head = head[:length]
	}
	if err := r.readFull(head, 0); err != nil {
		return nil, fmt.Errorf("fs: read boot area: %w", err)
	}

	switch {
	case hasStr(head[3:], "NTFS    "):
		return newNTFS(r, head)
	case hasStr(head[3:], "EXFAT   "):
		return newExFAT(r, head)
	case hasStr(head[0x52:], "FAT32   "):
		return newFAT(r, head, 32)
	case hasStr(head[0x36:], "FAT16   "):
		return newFAT(r, head, 16)
	case hasStr(head[0x36:], "FAT12   "):
		return newFAT(r, head, 12)
	case hasStr(head[0x36:], "FAT     "): // some formatters
		return newFAT(r, head, 16)
	case len(head) > 1080 && le16(head, 1024+56) == 0xEF53:
		return newExt(r, head)
	case isoProbe(r):
		return newISO(r)
	}
	// HFS+/APFS probes need reads beyond the first 64 KiB; try them last
	// only when the range is big enough.
	if length >= 2048 {
		return probeApple(r)
	}
	return nil, fmt.Errorf("fs: unrecognized filesystem in range at %#x", offset)
}

// isoProbe checks the ISO9660 primary volume descriptor at 0x8000.
func isoProbe(r rangeReader) bool {
	if r.size < 0x8000+7 {
		return false
	}
	b := make([]byte, 5)
	if err := r.readFull(b, 0x8001); err != nil {
		return false
	}
	return string(b) == "CD001"
}

// rangeReader presents src[offset:offset+size] as an absolute reader.
type rangeReader struct {
	src  Reader
	off  int64
	size int64
}

func (r rangeReader) Size() int64 { return r.size }

func (r rangeReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if off >= r.size {
		return 0, io.EOF
	}
	n := len(p)
	if rem := r.size - off; rem < int64(n) {
		n = int(rem)
	}
	got, err := r.src.ReadAt(p[:n], r.off+off)
	if err == nil && got < len(p) {
		err = io.EOF
	}
	return got, err
}

// readFull reads exactly len(p) bytes at off within the range.
func (r rangeReader) readFull(p []byte, off int64) error {
	got := 0
	for got < len(p) {
		n, err := r.ReadAt(p[got:], off+int64(got))
		got += n
		if err != nil {
			return err
		}
	}
	return nil
}

func hasStr(b []byte, s string) bool {
	if len(b) < len(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if b[i] != s[i] {
			return false
		}
	}
	return true
}

// splitPath normalizes an absolute path into components. The root is
// represented as an empty slice.
func splitPath(p string) []string {
	for len(p) > 0 && p[0] == '/' {
		p = p[1:]
	}
	if p == "" {
		return nil
	}
	var comps []string
	start := 0
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' {
			if i > start {
				comps = append(comps, p[start:i])
			}
			start = i + 1
		}
	}
	return comps
}

// joinPath builds a canonical absolute path from components.
func joinPath(comps []string) string {
	if len(comps) == 0 {
		return "/"
	}
	s := ""
	for _, c := range comps {
		s += "/" + c
	}
	return s
}
