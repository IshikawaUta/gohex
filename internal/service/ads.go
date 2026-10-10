package service

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/fs"
)

// FsStreams lists the named alternate data streams (ADS) of a file
// inside an NTFS image. The unnamed default stream is excluded — it is
// the file body, already visible via FsStat/FsRead. Filesystems
// without ADS support (FAT, ext, HFS+, ISO) return an empty list and
// no error, so callers can probe unconditionally.
func (a *App) FsStreams(path string, offset, size int64, fsPath string) ([]fs.Stream, error) {
	abs := absPath(path)
	f, err := a.fsOpen(abs, offset, size)
	if err != nil {
		return nil, err
	}
	streams, ok, err := fs.ADSStreams(f, normalizeFsPath(fsPath))
	if err != nil {
		return nil, err
	}
	if !ok {
		return []fs.Stream{}, nil
	}
	if streams == nil {
		streams = []fs.Stream{}
	}
	return streams, nil
}

// adsSource adapts one named alternate stream to core.Source so it can
// be opened as an ordinary hex document.
type adsSource struct {
	f      fs.FS
	path   string
	name   string
	size   int64
	parent string
}

func (s *adsSource) Name() string { return s.parent + ":" + s.name }
func (s *adsSource) Size() int64  { return s.size }
func (s *adsSource) ReadAt(p []byte, off int64) (int, error) {
	return fs.ADSReadAt(s.f, s.path, s.name, off, p)
}
func (s *adsSource) Close() error { return nil }

// FsOpenStream opens one named alternate data stream of an NTFS file
// as a hex document (read-only, audited). Compressed/encrypted
// streams are refused — the reader does not implement those codecs
// and guessing would taint evidence.
func (a *App) FsOpenStream(path string, offset, size int64, fsPath, stream string) (DocInfo, error) {
	if stream == "" {
		return DocInfo{}, errors.New("service: empty stream name")
	}
	abs := absPath(path)
	fsPath = normalizeFsPath(fsPath)
	f, err := a.fsOpen(abs, offset, size)
	if err != nil {
		return DocInfo{}, err
	}
	var found *fs.Stream
	streams, _, serr := fs.ADSStreams(f, fsPath)
	if serr != nil {
		return DocInfo{}, serr
	}
	for i := range streams {
		if streams[i].Name == stream {
			found = &streams[i]
			break
		}
	}
	if found == nil {
		return DocInfo{}, fmt.Errorf("service: stream %q not found in %q", stream, fsPath)
	}
	if found.Compressed || found.Encrypted {
		return DocInfo{}, fmt.Errorf("service: stream %q is %s — not readable",
			stream, map[bool]string{true: "compressed", false: "encrypted"}[found.Compressed])
	}
	src := &adsSource{f: f, path: fsPath, name: stream, size: found.Size, parent: fsPath}
	doc, err := a.openContainer(src.Name(), src, map[string]string{
		"op":     "fs:stream-open",
		"stream": stream,
		"file":   fsPath,
		"ads":    "true",
	})
	if err != nil {
		return DocInfo{}, err
	}
	return doc, nil
}

// FsStreamExport copies one named alternate stream out of the image
// to dstPath, recording the SHA-256 of the copy in the audit log
// (chain of custody). The destination must not exist.
func (a *App) FsStreamExport(path string, offset, size int64, fsPath, stream, dstPath string) (SaveResult, error) {
	if stream == "" {
		return SaveResult{}, errors.New("service: empty stream name")
	}
	abs := absPath(path)
	fsPath = normalizeFsPath(fsPath)
	f, err := a.fsOpen(abs, offset, size)
	if err != nil {
		return SaveResult{}, err
	}
	var found *fs.Stream
	streams, _, serr := fs.ADSStreams(f, fsPath)
	if serr != nil {
		return SaveResult{}, serr
	}
	for i := range streams {
		if streams[i].Name == stream {
			found = &streams[i]
			break
		}
	}
	if found == nil {
		return SaveResult{}, fmt.Errorf("service: stream %q not found in %q", stream, fsPath)
	}
	if found.Compressed || found.Encrypted {
		return SaveResult{}, fmt.Errorf("service: stream %q is not readable", stream)
	}
	dst, oerr := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if oerr != nil {
		return SaveResult{}, fmt.Errorf("service: stream export: %w", oerr)
	}
	abort := func(err error) (SaveResult, error) {
		dst.Close()
		os.Remove(dstPath)
		_ = a.log.Log(audit.Event{
			Action: audit.ActionExport,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"file": fsPath + ":" + stream, "error": err.Error()},
		})
		return SaveResult{}, err
	}
	h := sha256.New()
	var written int64
	buf := make([]byte, maxReadWindow)
	for written < found.Size {
		n, rerr := fs.ADSReadAt(f, fsPath, stream, written, buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				_ = dst.Close()
				return abort(werr)
			}
			h.Write(buf[:n])
			written += int64(n)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			_ = dst.Close()
			return abort(rerr)
		}
		if n == 0 {
			break
		}
	}
	if err := dst.Close(); err != nil {
		return abort(err)
	}
	sum := fmt.Sprintf("%x", h.Sum(nil))
	_ = a.log.Log(audit.Event{
		Action: audit.ActionExport,
		Target: abs,
		Result: audit.ResultOK,
		Detail: map[string]string{
			"file":    fsPath + ":" + stream,
			"dest":    dstPath,
			"sha256":  sum,
			"bytes":   fmt.Sprintf("%d", written),
			"stream":  "true",
			"fsType":  f.Type(),
			"fsLabel": f.Label(),
		},
	})
	return SaveResult{Path: dstPath, BytesSaved: written, Mode: "sandbox", SHA256: sum}, nil
}
