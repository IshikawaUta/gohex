package service

import (
	"bytes"
	"crypto/sha256"
	stdhex "encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/print"
)

// ExportView renders [offset, offset+length) of a document as a
// hex-grid exhibit (offset + hex bytes + ASCII gutter) and writes it
// to dstPath as PDF or PNG. The format is taken from the destination
// extension so the save dialog alone picks the shape. The copy is
// hashed and audited like every other export; the document itself is
// untouched.
func (a *App) ExportView(id int64, offset, length int64, dstPath string) (SaveResult, error) {
	d, err := a.lookup(id)
	if err != nil {
		return SaveResult{}, err
	}
	auditFail := func(err error) (SaveResult, error) {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionExport,
			Target: dstPath,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "export-view", "doc": strconv.FormatInt(id, 10), "error": err.Error()},
		})
		return SaveResult{}, err
	}
	if offset < 0 || length <= 0 {
		return auditFail(errors.New("service: export view: invalid range"))
	}
	if length > print.MaxLines*print.Width {
		return auditFail(fmt.Errorf("service: export view: range exceeds %d bytes (%d lines max)",
			print.MaxLines*print.Width, print.MaxLines))
	}
	dstPath = strings.TrimSpace(dstPath)
	if dstPath == "" {
		return auditFail(errors.New("service: export view: empty destination"))
	}
	lower := strings.ToLower(dstPath)
	data, err := d.document.ReadCopy(offset, length)
	if err != nil {
		return auditFail(fmt.Errorf("service: export view: %w", err))
	}
	lines := print.Lines(data, offset)
	name := d.path
	if name == "" {
		name = fmt.Sprintf("Untitled-%d", id)
	}
	title := fmt.Sprintf("%s  [%#x, %#x)", name, offset, offset+int64(len(data)))
	var out bytes.Buffer
	var format string
	switch {
	case strings.HasSuffix(lower, ".pdf"):
		format = "pdf"
		if err := print.PDF(&out, title, lines); err != nil {
			return auditFail(err)
		}
	case strings.HasSuffix(lower, ".png"):
		format = "png"
		if err := print.PNG(&out, title, lines); err != nil {
			return auditFail(err)
		}
	default:
		return auditFail(fmt.Errorf("service: export view: unsupported format (use .pdf or .png): %s", dstPath))
	}
	payload := out.Bytes()

	abs := absPath(dstPath)
	dst, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return auditFail(fmt.Errorf("service: export view: %w", err))
	}
	abort := func(err error) (SaveResult, error) {
		dst.Close()
		os.Remove(abs)
		_ = a.log.Log(audit.Event{
			Action: audit.ActionExport,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "export-view", "doc": strconv.FormatInt(id, 10), "error": err.Error()},
		})
		return SaveResult{}, err
	}
	h := sha256.New()
	h.Write(payload)
	if _, err := dst.Write(payload); err != nil {
		return abort(fmt.Errorf("service: export view: %w", err))
	}
	if err := dst.Close(); err != nil {
		return abort(fmt.Errorf("service: export view close: %w", err))
	}
	sum := stdhex.EncodeToString(h.Sum(nil))
	_ = a.log.Log(audit.Event{
		Action: audit.ActionExport,
		Target: abs,
		Result: audit.ResultOK,
		Hash:   "sha256:" + sum,
		Detail: map[string]string{
			"op":     "export-view",
			"doc":    strconv.FormatInt(id, 10),
			"format": format,
			"offset": strconv.FormatInt(offset, 10),
			"bytes":  strconv.FormatInt(int64(len(data)), 10),
		},
	})
	return SaveResult{Path: abs, BytesSaved: int64(len(payload)), Mode: "export-view", SHA256: sum}, nil
}
