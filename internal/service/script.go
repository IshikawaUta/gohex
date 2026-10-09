package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/core"
	encoding "github.com/IshikawaUta/gohex/internal/encoding" // package bincoding
	"github.com/IshikawaUta/gohex/internal/hex"
	"github.com/IshikawaUta/gohex/internal/script"
)

// maxScriptSize caps the source file of one automation script (1 MiB —
// comfortably above any real script, far below anything that could stall
// the interpreter at load time).
const maxScriptSize = 1 << 20

// ScriptResult is the outcome of one ScriptRun. A script that ran but
// failed (syntax error, runtime error, limit hit) is reported in Error
// with a non-zero DurationMs, not as a Go error — only infrastructure
// problems (missing file, unreadable path) fail the call itself.
type ScriptResult struct {
	Output     string `json:"output"`
	Error      string `json:"error,omitempty"`
	DurationMs int64  `json:"durationMs"`
	Steps      uint64 `json:"steps"`
}

// ScriptRun executes a Starlark (.star) script with read-only access to
// the currently open documents through the sandboxed "gohex" module
// (docs/read/find/hash/version). The interpreter is bounded by a
// wall-clock timeout and a step limit; there is no filesystem, network,
// clock or randomness inside the sandbox. Every run is recorded in the
// audit log.
func (a *App) ScriptRun(path string) (ScriptResult, error) {
	if path == "" {
		return ScriptResult{}, errors.New("service: script: empty path")
	}
	abs := absPath(path)
	fi, err := os.Stat(abs)
	if err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionScript,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "script-run", "error": err.Error()},
		})
		return ScriptResult{}, fmt.Errorf("service: script: %w", err)
	}
	if fi.IsDir() {
		return ScriptResult{}, fmt.Errorf("service: script: %q is a directory", filepath.Base(abs))
	}
	if fi.Size() > maxScriptSize {
		return ScriptResult{}, fmt.Errorf("service: script %q is %d bytes (limit %d)",
			filepath.Base(abs), fi.Size(), maxScriptSize)
	}
	src, err := os.ReadFile(abs)
	if err != nil {
		return ScriptResult{}, fmt.Errorf("service: script: %w", err)
	}

	start := time.Now()
	res, runErr := script.Run(context.Background(), &scriptHost{app: a}, filepath.Base(abs), src)
	out := ScriptResult{
		Output:     res.Output,
		DurationMs: time.Since(start).Milliseconds(),
		Steps:      res.Steps,
	}
	if runErr != nil {
		out.Error = runErr.Error()
		_ = a.log.Log(audit.Event{
			Action: audit.ActionScript,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{
				"op":       "script-run",
				"mode":     "read-only",
				"error":    runErr.Error(),
				"duration": fmt.Sprintf("%dms", out.DurationMs),
			},
		})
		return out, nil
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionScript,
		Target: abs,
		Result: audit.ResultOK,
		Detail: map[string]string{
			"op":       "script-run",
			"mode":     "read-only",
			"duration": fmt.Sprintf("%dms", out.DurationMs),
		},
	})
	return out, nil
}

// scriptHost is the document access surface handed to the script engine.
// It is only ever called from the script's own goroutine.
type scriptHost struct{ app *App }

func (h *scriptHost) Docs() []script.Doc {
	infos := h.app.ListDocuments()
	docs := make([]script.Doc, 0, len(infos))
	for _, info := range infos {
		docs = append(docs, script.Doc{ID: info.ID, Name: info.Name, Size: info.Size})
	}
	return docs
}

func (h *scriptHost) Read(id, offset, size int64) ([]byte, error) {
	d, err := h.app.lookup(id)
	if err != nil {
		return nil, err
	}
	if offset < 0 {
		return nil, core.ErrNegativeOffset
	}
	docSize := d.document.Size()
	if offset >= docSize {
		return nil, nil
	}
	if size <= 0 || size > script.MaxReadSize {
		size = script.MaxReadSize
	}
	if offset+size > docSize {
		size = docSize - offset
	}
	buf := make([]byte, size)
	n, err := d.document.ReadAt(buf, offset)
	if n == 0 && err != nil && err != io.EOF {
		return nil, fmt.Errorf("service: script read: %w", err)
	}
	return buf[:n], nil
}

func (h *scriptHost) Find(id int64, text string, offset int64, limit int) ([]int64, error) {
	d, err := h.app.lookup(id)
	if err != nil {
		return nil, err
	}
	if offset < 0 {
		return nil, core.ErrNegativeOffset
	}
	if limit <= 0 || limit > script.MaxFindResults {
		limit = script.MaxFindResults
	}
	p, err := hex.NewTextPattern(text, encoding.ASCII, false)
	if err != nil {
		return nil, err
	}
	size := d.document.Size()
	if offset > size {
		offset = size
	}
	hits, err := hex.FindAll(d.document, p, offset, size, limit)
	if err != nil {
		return nil, err
	}
	offsets := make([]int64, 0, len(hits))
	for _, m := range hits {
		offsets = append(offsets, m.Start)
	}
	return offsets, nil
}
