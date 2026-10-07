package service

import (
	"crypto/sha256"
	stdhex "encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/core"
	"github.com/IshikawaUta/gohex/internal/disk"
	encoding "github.com/IshikawaUta/gohex/internal/encoding" // package bincoding
	"github.com/IshikawaUta/gohex/internal/fs"
	"github.com/IshikawaUta/gohex/internal/hex"
	"github.com/IshikawaUta/gohex/internal/image"
)

// exportChunk is the copy unit used when extracting files out of an image.
const exportChunk = 256 << 10

// ImageInfo describes a disk-image container without opening a tab.
type ImageInfo struct {
	Path   string `json:"path"`
	Format string `json:"format"` // raw | ewf | vhd | qcow2 | vmdk | vhdx
	Size   int64  `json:"size"`
}

// PartitionInfo is one partition plus what lives inside it.
type PartitionInfo struct {
	Partition  disk.Partition `json:"partition"`
	Filesystem string         `json:"filesystem,omitempty"` // "ext4", "ntfs", ... ("" = none/unknown)
	Label      string         `json:"fsLabel,omitempty"`
}

// DiskLayout is the parsed partition table of an image with a filesystem
// probed per partition.
type DiskLayout struct {
	Kind       string          `json:"kind"` // none | mbr | gpt
	DiskGUID   string          `json:"diskGuid,omitempty"`
	MBRDiskSig uint32          `json:"mbrDiskSig,omitempty"`
	Warnings   []string        `json:"warnings,omitempty"`
	Partitions []PartitionInfo `json:"partitions"`
}

// FileSystemInfo describes a probed filesystem at a byte range.
type FileSystemInfo struct {
	Type   string `json:"type"`
	Label  string `json:"label"`
	Size   int64  `json:"size"`
	Offset int64  `json:"offset"`
}

// imageSource adapts an image container reader to core.Source so a whole
// image can be hex-viewed like any other file.
type imageSource struct {
	image.Reader
	name string
}

func (s *imageSource) Name() string { return s.name }

// subSource exposes the byte range [base, base+length) of an open container
// as a standalone Source, so a single partition can become its own tab.
type subSource struct {
	r    io.ReaderAt
	name string
	base int64
	size int64
	cls  io.Closer
}

func (s *subSource) Name() string { return s.name }
func (s *subSource) Size() int64  { return s.size }

func (s *subSource) Close() error {
	if s.cls != nil {
		return s.cls.Close()
	}
	return nil
}

func (s *subSource) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, core.ErrNegativeOffset
	}
	if off >= s.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > s.size-off {
		want = int(s.size - off)
	}
	n, err := s.r.ReadAt(p[:want], s.base+off)
	if n < len(p) {
		if err == nil || errors.Is(err, io.EOF) {
			err = io.EOF
		}
		return n, err
	}
	return n, err
}

// --- images --------------------------------------------------------------

// ProbeImage reports the container format and virtual size of an image
// without opening a document.
func (a *App) ProbeImage(path string) (ImageInfo, error) {
	abs := absPath(path)
	img, err := image.Open(abs)
	if err != nil {
		return ImageInfo{}, err
	}
	defer img.Close()
	return ImageInfo{Path: abs, Format: img.Format(), Size: img.Size()}, nil
}

// OpenImage opens a disk-image container (RAW, EWF/E01, VHD, QCOW2, VMDK,
// VHDX) as a read-only document, exactly like OpenFile but through the image
// decoder. Detection is magic-based, so the file name never matters.
func (a *App) OpenImage(path string) (DocInfo, error) {
	abs := absPath(path)
	img, err := image.Open(abs)
	if err != nil {
		return DocInfo{}, err
	}
	return a.openContainer(abs, &imageSource{Reader: img, name: abs},
		map[string]string{"format": img.Format()})
}

// OpenRange opens [offset, offset+size) of an image or raw disk as its own
// document — the usual way to hex-view a single partition. A size <= 0 runs
// to the end of the medium.
func (a *App) OpenRange(path string, offset, size int64) (DocInfo, error) {
	abs := absPath(path)
	img, err := image.Open(abs)
	if err != nil {
		return DocInfo{}, err
	}
	if offset < 0 || offset > img.Size() {
		img.Close()
		return DocInfo{}, fmt.Errorf("service: offset %d outside %q (%d bytes)", offset, abs, img.Size())
	}
	if size <= 0 || offset+size > img.Size() {
		size = img.Size() - offset
	}
	src := &subSource{r: img, name: fmt.Sprintf("%s[%d:%d]", filepath.Base(abs), offset, offset+size),
		base: offset, size: size, cls: img}
	return a.openContainer(abs, src, map[string]string{
		"offset": fmt.Sprintf("%d", offset),
		"size":   fmt.Sprintf("%d", size),
	})
}

// openContainer registers an already-open read-only source as a tab.
func (a *App) openContainer(path string, src core.Source, detail map[string]string) (DocInfo, error) {
	d := &doc{document: hex.New(src), path: path, src: src, enc: encoding.ASCII}
	a.mu.Lock()
	a.nextID++
	d.id = a.nextID
	a.docs[d.id] = d
	a.order = append(a.order, d.id)
	a.cfg.AddRecent(path)
	a.mu.Unlock()
	detail["mode"] = "read-only"
	detail["size"] = fmt.Sprintf("%d", src.Size())
	_ = a.log.Log(audit.Event{
		Action: audit.ActionOpen,
		Target: path,
		Result: audit.ResultOK,
		Detail: detail,
	})
	a.event("docs:changed", nil)
	return a.DocumentInfo(d.id)
}

// --- partitions ----------------------------------------------------------

// Partitions parses the partition table of an image or raw disk and probes
// the filesystem living in each partition. It opens nothing: evidence is
// only read, never written.
func (a *App) Partitions(path string) (DiskLayout, error) {
	abs := absPath(path)
	img, err := image.Open(abs)
	if err != nil {
		return DiskLayout{}, err
	}
	defer img.Close()

	t, err := disk.Parse(img)
	if err != nil {
		return DiskLayout{}, err
	}
	out := DiskLayout{
		Kind:       string(t.Kind),
		DiskGUID:   t.DiskGUID,
		MBRDiskSig: t.MBRDiskSig,
		Warnings:   t.Warnings,
		Partitions: make([]PartitionInfo, 0, len(t.Partitions)),
	}
	for _, p := range t.Partitions {
		pi := PartitionInfo{Partition: p}
		if f, ferr := fs.Probe(img, p.Start, p.Size); ferr == nil {
			pi.Filesystem, pi.Label = f.Type(), f.Label()
		}
		out.Partitions = append(out.Partitions, pi)
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionOpen,
		Target: abs,
		Result: audit.ResultOK,
		Detail: map[string]string{
			"op":         "partitions",
			"kind":       out.Kind,
			"partitions": fmt.Sprintf("%d", len(out.Partitions)),
		},
	})
	return out, nil
}

// --- filesystem browsing -------------------------------------------------

func fsKey(path string, offset, size int64) string {
	return fmt.Sprintf("%s\x00%d\x00%d", path, offset, size)
}

// fsOpen returns (opening if needed) a cached read-only filesystem view.
// Sessions stay open for the lifetime of the App so repeated directory
// listings do not re-parse the superblock; they are closed by App.Close.
func (a *App) fsOpen(path string, offset, size int64) (fs.FS, error) {
	if offset < 0 {
		return nil, errors.New("service: negative filesystem offset")
	}
	key := fsKey(path, offset, size)
	a.mu.Lock()
	if s, ok := a.fss[key]; ok {
		a.mu.Unlock()
		return s.f, nil
	}
	a.mu.Unlock()

	img, err := image.Open(path)
	if err != nil {
		return nil, err
	}
	f, err := fs.Probe(img, offset, size)
	if err != nil {
		img.Close()
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if s, ok := a.fss[key]; ok { // another goroutine won the race
		img.Close()
		return s.f, nil
	}
	a.fss[key] = &fsSession{r: img, f: f}
	return f, nil
}

// ProbeFileSystem identifies the filesystem at [offset, offset+size) of an
// image. A size <= 0 runs to the end of the medium.
func (a *App) ProbeFileSystem(path string, offset, size int64) (FileSystemInfo, error) {
	abs := absPath(path)
	f, err := a.fsOpen(abs, offset, size)
	if err != nil {
		return FileSystemInfo{}, err
	}
	return FileSystemInfo{Type: f.Type(), Label: f.Label(), Size: f.TotalSize(), Offset: offset}, nil
}

// FsList returns the entries of a directory inside the image. dir is an
// absolute slash-separated path ("/" for the root).
func (a *App) FsList(path string, offset, size int64, dir string) ([]fs.Entry, error) {
	abs := absPath(path)
	f, err := a.fsOpen(abs, offset, size)
	if err != nil {
		return nil, err
	}
	entries, err := f.List(normalizeFsPath(dir))
	if err != nil {
		return nil, err
	}
	if entries == nil {
		entries = []fs.Entry{}
	}
	return entries, nil
}

// FsStat returns the entry at fsPath inside the image.
func (a *App) FsStat(path string, offset, size int64, fsPath string) (fs.Entry, error) {
	abs := absPath(path)
	f, err := a.fsOpen(abs, offset, size)
	if err != nil {
		return fs.Entry{}, err
	}
	return f.Stat(normalizeFsPath(fsPath))
}

// FsRead returns up to length bytes of a file inside the image starting at
// off. length is clamped to the read window so a hostile request cannot
// exhaust memory.
func (a *App) FsRead(path string, offset, size int64, fsPath string, off, length int64) ([]byte, error) {
	if off < 0 {
		return nil, errors.New("service: negative read offset")
	}
	if length <= 0 {
		return nil, nil
	}
	if length > maxReadWindow {
		length = maxReadWindow
	}
	abs := absPath(path)
	f, err := a.fsOpen(abs, offset, size)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, length)
	n, err := f.ReadAt(normalizeFsPath(fsPath), off, buf)
	if n > 0 && (err == nil || errors.Is(err, io.EOF)) {
		return buf[:n], nil
	}
	if err == nil {
		err = io.EOF
	}
	if errors.Is(err, io.EOF) && n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

// FsExport copies a file out of the image to dstPath, recording the SHA-256
// of the copy in the audit log (chain of custody). The destination must not
// exist: evidence exports are never silently overwritten.
func (a *App) FsExport(path string, offset, size int64, fsPath, dstPath string) (SaveResult, error) {
	abs := absPath(path)
	fsPath = normalizeFsPath(fsPath)
	f, err := a.fsOpen(abs, offset, size)
	if err != nil {
		return SaveResult{}, err
	}
	st, err := f.Stat(fsPath)
	if err != nil {
		return SaveResult{}, err
	}
	if st.Dir {
		return SaveResult{}, fmt.Errorf("service: %q is a directory", fsPath)
	}

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return SaveResult{}, fmt.Errorf("service: export: %w", err)
	}
	abort := func(err error) (SaveResult, error) {
		dst.Close()
		os.Remove(dstPath)
		_ = a.log.Log(audit.Event{
			Action: audit.ActionExport,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"file": fsPath, "error": err.Error()},
		})
		return SaveResult{}, err
	}

	h := sha256.New()
	var written int64
	buf := make([]byte, exportChunk)
	for off := int64(0); off < st.Size; off += int64(len(buf)) {
		want := int64(len(buf))
		if remain := st.Size - off; remain < want {
			want = remain
		}
		n, rerr := f.ReadAt(fsPath, off, buf[:want])
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return abort(fmt.Errorf("service: export write: %w", werr))
			}
			h.Write(buf[:n])
			written += int64(n)
		}
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return abort(fmt.Errorf("service: export read: %w", rerr))
		}
		if n < int(want) {
			break
		}
	}
	if err := dst.Close(); err != nil {
		return abort(fmt.Errorf("service: export close: %w", err))
	}
	if written != st.Size {
		os.Remove(dstPath)
		return SaveResult{}, fmt.Errorf("service: export short copy: %d of %d bytes", written, st.Size)
	}
	sum := stdhex.EncodeToString(h.Sum(nil))
	_ = a.log.Log(audit.Event{
		Action: audit.ActionExport,
		Target: abs,
		Result: audit.ResultOK,
		Hash:   "sha256:" + sum,
		Detail: map[string]string{
			"file":  fsPath,
			"dest":  dstPath,
			"bytes": fmt.Sprintf("%d", written),
		},
	})
	return SaveResult{Path: dstPath, BytesSaved: written, Mode: "export", SHA256: sum}, nil
}

// normalizeFsPath makes a UI path absolute and free of trailing slashes
// (except for the root).
func normalizeFsPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	return p
}

func absPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}
