package service

import (
	"errors"
	"strconv"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/memory"
)

// MemoryInfo reports the format, size and physical segment map of a memory
// capture. The capture is opened read-only and only its parsed metadata is
// returned; the access is recorded in the audit log.
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

// MemoryLocate maps a physical address inside the capture onto a file offset
// so the caller can open the covering bytes in the hex view. It re-reads the
// capture's headers only; the access is already covered by the MemoryInfo
// audit record, so no second record is written here.
func (a *App) MemoryLocate(path string, phys int64) (memory.Location, error) {
	if path == "" {
		return memory.Location{}, errors.New("service: memory: empty path")
	}
	mc, err := memory.Open(absPath(path))
	if err != nil {
		return memory.Location{}, err
	}
	return mc.Locate(phys)
}
