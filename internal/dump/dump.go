// Package dump parses crash reports that are not memory dumps: macOS/iOS
// .ips files, Android tombstones and Windows Error Reporting (WER) reports.
// The raw capture formats themselves (ELF core, minidump, PAGEDU64) live in
// internal/memory; this package handles the text/JSON reports a triage
// workflow collects next to them.
//
// Parsing is read-only and defensive: detection is content-based (never
// extension-based), a malformed report yields an error instead of a partial
// guess, and no symbolication is attempted — frames are reported exactly as
// the file states them.
package dump

import (
	"errors"
	"fmt"
)

// MaxReportSize is the largest report Parse accepts (8 MiB). Crash reports
// are text; anything larger is not one of the supported formats.
const MaxReportSize = 8 << 20

// Report is the parsed summary of a crash report. All fields are populated
// on a best-effort basis: what the format guarantees is filled, the rest
// stays empty rather than inventing values.
type Report struct {
	// Source is the platform: "macos", "ios", "android" or "windows".
	Source string `json:"source"`
	// Format is the concrete format: "ips", "tombstone" or "wer".
	Format string `json:"format"`
	// App is the crashed process or application name.
	App string `json:"app"`
	// Version is the application/OS version when the report states one.
	Version string `json:"version"`
	// Timestamp is the crash time in RFC 3339 (UTC) or the raw string the
	// format provides when it is not a machine-readable time.
	Timestamp string `json:"timestamp"`
	// Type is the crash classification: bug type (ips), signal (tombstone)
	// or event type (wer).
	Type string `json:"type"`
	// Summary is a one-line human description of the crash.
	Summary string `json:"summary"`
	// PID and TID are the process/thread ids when present.
	PID int `json:"pid"`
	TID int `json:"tid"`
	// Frames is the number of frames in the faulting/backtrace stack.
	Frames int `json:"frames"`
	// TopFrames holds up to the first 5 frames, verbatim from the report.
	TopFrames []string `json:"topFrames"`
	// Details carries format-specific extras (signal code, fault address,
	// build fingerprint, exception records, ...).
	Details map[string]string `json:"details"`
}

// ErrUnrecognized is returned when no supported format matches the input.
var ErrUnrecognized = errors.New("dump: unrecognized crash report format")

// Parse identifies and parses a crash report from its content. The input
// must be the complete report (at most MaxReportSize bytes).
func Parse(data []byte) (*Report, error) {
	if len(data) == 0 {
		return nil, errors.New("dump: empty input")
	}
	if len(data) > MaxReportSize {
		return nil, fmt.Errorf("dump: report exceeds %d bytes", MaxReportSize)
	}
	if isIPS(data) {
		return parseIPS(data)
	}
	if isTombstone(data) {
		return parseTombstone(data)
	}
	if isWER(data) {
		return parseWER(data)
	}
	return nil, ErrUnrecognized
}

// head returns up to n leading bytes; sniffing never needs the whole file.
func head(data []byte, n int) []byte {
	if len(data) < n {
		return data
	}
	return data[:n]
}
