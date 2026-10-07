package service

import (
	"crypto/sha256"
	stdhex "encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/image"
	"github.com/IshikawaUta/gohex/internal/recovery"
)

const (
	// defaultCarveMax bounds a scan when the caller does not ask for a limit.
	// The UI renders the whole result list, so an unbounded run over a disk
	// image full of signatures would freeze it.
	defaultCarveMax = 10000
	// maxCarveMax is the hard ceiling a caller may request.
	maxCarveMax = 100000
)

// CarveTypes lists the file types the carver recognises, for the UI's
// type picker.
func (a *App) CarveTypes() []recovery.SpecInfo {
	return recovery.Types()
}

// CarveScan looks for embedded files inside path (or inside [from, to) of it
// when either bound is set) and returns their offsets and lengths. Evidence is
// only read: nothing is written back to the source.
//
// Results are ordered by offset and each entry's extent is known — either from
// a footer or from the file's own length field. Pass allowTruncated to also
// report objects whose footer lies past the scanned range.
func (a *App) CarveScan(path string, from, to int64, types []string, max int, allowTruncated bool) ([]recovery.Carved, error) {
	abs := absPath(path)
	if abs == "" {
		return nil, errors.New("service: carve: empty path")
	}
	if max <= 0 {
		max = defaultCarveMax
	}
	if max > maxCarveMax {
		max = maxCarveMax
	}
	img, err := image.Open(abs)
	if err != nil {
		return nil, err
	}
	defer img.Close()

	var lastPct int64 = -1
	opts := recovery.Options{
		From: from, To: to, Types: types, Max: max,
		AllowTruncated: allowTruncated,
		Progress: func(done, total int64) {
			if total <= 0 {
				return
			}
			pct := done * 100 / total
			if pct != lastPct {
				lastPct = pct
				a.event("progress", map[string]any{"op": "carve", "done": pct})
			}
		},
	}
	found, err := recovery.Carve(img, opts)
	if err != nil {
		return nil, err
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionSearch,
		Target: abs,
		Result: audit.ResultOK,
		Detail: map[string]string{
			"op":         "carve",
			"range":      fmt.Sprintf("%d..%d", from, to),
			"results":    fmt.Sprintf("%d", len(found)),
			"truncated":  fmt.Sprintf("%t", allowTruncated),
			"limit":      fmt.Sprintf("%d", max),
			"containers": fmt.Sprintf("%d", len(types)),
		},
	})
	return found, nil
}

// CarveExport writes one recovered object from path to dstPath. The destination
// must not exist, the copy is hashed, and both the success and the failure are
// recorded in the audit log.
func (a *App) CarveExport(path string, item recovery.Carved, dstPath string) (SaveResult, error) {
	abs := absPath(path)
	if abs == "" {
		return SaveResult{}, errors.New("service: carve export: empty path")
	}
	if item.Offset < 0 || item.Length <= 0 {
		return SaveResult{}, fmt.Errorf("service: carve export: invalid range %#x+%#x", item.Offset, item.Length)
	}
	if dstPath == "" {
		return SaveResult{}, errors.New("service: carve export: empty destination")
	}

	img, err := image.Open(abs)
	if err != nil {
		return SaveResult{}, err
	}
	defer img.Close()

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return SaveResult{}, fmt.Errorf("service: carve export: %w", err)
	}
	abort := func(err error) (SaveResult, error) {
		dst.Close()
		os.Remove(dstPath)
		_ = a.log.Log(audit.Event{
			Action: audit.ActionExport,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "carve", "dest": dstPath, "error": err.Error()},
		})
		return SaveResult{}, err
	}

	h := sha256.New()
	written, err := recovery.Extract(img, item, io.MultiWriter(dst, h))
	if err != nil {
		return abort(fmt.Errorf("service: carve export: %w", err))
	}
	if err := dst.Close(); err != nil {
		return abort(fmt.Errorf("service: carve export close: %w", err))
	}
	if written != item.Length {
		return abort(fmt.Errorf("service: carve export short copy: %d of %d bytes", written, item.Length))
	}

	sum := stdhex.EncodeToString(h.Sum(nil))
	_ = a.log.Log(audit.Event{
		Action: audit.ActionExport,
		Target: abs,
		Result: audit.ResultOK,
		Hash:   "sha256:" + sum,
		Detail: map[string]string{
			"op":     "carve",
			"type":   item.Type,
			"offset": fmt.Sprintf("%d", item.Offset),
			"dest":   dstPath,
			"bytes":  fmt.Sprintf("%d", written),
		},
	})
	return SaveResult{Path: dstPath, BytesSaved: written, Mode: "carve", SHA256: sum}, nil
}
