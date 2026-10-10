package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/dump"
)

// maxDumpReport caps one crash report file (8 MiB — reports are text).
const maxDumpReport = dump.MaxReportSize

// DumpInfo parses a crash report (macOS/iOS .ips, Android tombstone or
// Windows WER) read-only and returns its structured summary. The parse is
// recorded in the audit log like every other file open.
func (a *App) DumpInfo(path string) (dump.Report, error) {
	if path == "" {
		return dump.Report{}, errors.New("service: dump: empty path")
	}
	abs := absPath(path)
	fi, err := os.Stat(abs)
	if err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionOpen,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "dump", "error": err.Error()},
		})
		return dump.Report{}, fmt.Errorf("dump: %w", err)
	}
	if fi.Size() > maxDumpReport {
		return dump.Report{}, fmt.Errorf("dump: %s is %d bytes (limit %d)",
			filepath.Base(abs), fi.Size(), maxDumpReport)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return dump.Report{}, fmt.Errorf("dump: %w", err)
	}
	rep, err := dump.Parse(data)
	if err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionOpen,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "dump", "error": err.Error()},
		})
		return dump.Report{}, err
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionOpen,
		Target: abs,
		Result: audit.ResultOK,
		Detail: map[string]string{
			"op":     "dump",
			"format": rep.Format,
			"source": rep.Source,
			"mode":   "read-only",
		},
	})
	return *rep, nil
}
