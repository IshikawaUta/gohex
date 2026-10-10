package dump

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

var (
	tsBanner   = []byte("*** *** *** ***")
	tsFinger   = []byte("Build fingerprint:")
	tsBacktr   = []byte("backtrace:")
	tsPidLine  = regexp.MustCompile(`^pid:\s*(\d+),\s*tid:\s*(\d+)(?:,\s*name:\s*(\S+))?`)
	tsSignal   = regexp.MustCompile(`^signal (\d+) \(([^)]+)\)(?:, code (-?\d+) \(([^)]+)\))?(?:, fault addr (0x[0-9a-fA-F]+))?`)
	tsFrame    = regexp.MustCompile(`^\s*#\d+\s+pc\s+([0-9a-fA-F]+)\s+(\S+)(?:\s+\((.*)\))?`)
	tsTimeUnix = regexp.MustCompile(`^Timestamp:\s*(.+)$`)
)

// isTombstone sniffs an Android tombstone: the standard banner or the
// build-fingerprint + backtrace combination.
func isTombstone(data []byte) bool {
	hasFP := bytes.Contains(head(data, 4096), tsFinger)
	if bytes.HasPrefix(bytes.TrimLeft(data, " \t"), tsBanner) {
		return true
	}
	return hasFP && bytes.Contains(head(data, 8192), tsBacktr)
}

func parseTombstone(data []byte) (*Report, error) {
	rep := &Report{
		Source:  "android",
		Format:  "tombstone",
		Details: map[string]string{},
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	inBacktrace := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Build fingerprint:"):
			rep.Details["fingerprint"] = strings.TrimSpace(
				strings.TrimPrefix(trimmed, "Build fingerprint:"))
		case strings.HasPrefix(trimmed, "Cmdline:"):
			rep.App = strings.TrimSpace(strings.TrimPrefix(trimmed, "Cmdline:"))
		case strings.HasPrefix(trimmed, "Abort message:"):
			rep.Details["abortMessage"] = strings.TrimSpace(
				strings.TrimPrefix(trimmed, "Abort message:"))
		case tsPidLine.MatchString(trimmed):
			m := tsPidLine.FindStringSubmatch(trimmed)
			rep.PID = atoi(m[1])
			rep.TID = atoi(m[2])
			if m[3] != "" && rep.App == "" {
				rep.App = m[3]
			}
		case tsSignal.MatchString(trimmed):
			m := tsSignal.FindStringSubmatch(trimmed)
			rep.Type = m[2]
			if m[4] != "" {
				rep.Details["code"] = m[3] + " (" + m[4] + ")"
			}
			if m[5] != "" {
				rep.Details["faultAddr"] = m[5]
			}
		case tsTimeUnix.MatchString(trimmed):
			if rep.Timestamp == "" {
				rep.Timestamp = strings.TrimSpace(tsTimeUnix.FindStringSubmatch(trimmed)[1])
			}
		case trimmed == "backtrace:":
			inBacktrace = true
			continue
		}
		if inBacktrace {
			if m := tsFrame.FindStringSubmatch(line); m != nil {
				rep.Frames++
				if len(rep.TopFrames) < 5 {
					frame := "pc " + m[1] + "  " + m[2]
					if m[3] != "" {
						frame += " (" + m[3] + ")"
					}
					rep.TopFrames = append(rep.TopFrames, frame)
				}
			} else if trimmed != "" && !strings.HasPrefix(trimmed, "backtrace:") && rep.Frames > 0 &&
				!strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				inBacktrace = false
			}
		}
	}
	if rep.Type == "" && rep.Frames == 0 {
		return nil, fmt.Errorf("dump: tombstone: no signal or backtrace found")
	}
	if rep.App == "" {
		rep.App = "unknown process"
	}
	rep.Summary = "android tombstone — " + rep.App
	if rep.Type != "" {
		rep.Summary += ", signal " + rep.Type
	}
	return rep, nil
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
