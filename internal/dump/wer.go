package dump

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// isWER sniffs a Windows Error Reporting report: key=value lines with an
// EventType and report identifiers or signature records.
func isWER(data []byte) bool {
	h := head(data, 4096)
	if !bytes.Contains(h, []byte("EventType=")) {
		return false
	}
	return bytes.Contains(h, []byte("ReportIdentifier=")) ||
		bytes.Contains(h, []byte("Sig[")) ||
		bytes.Contains(h, []byte("ReportType="))
}

func parseWER(data []byte) (*Report, error) {
	rep := &Report{
		Source:  "windows",
		Format:  "wer",
		Details: map[string]string{},
	}
	var sigNames, sigValues []string
	for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key, val := line[:eq], line[eq+1:]
		switch {
		case key == "EventType":
			rep.Type = val
		case key == "AppName":
			rep.App = val
		case key == "AppVerName":
			rep.Version = val
		case key == "EventTime":
			if t, ok := filetimeUTC(val); ok {
				rep.Timestamp = t
			} else {
				rep.Details["eventTime"] = val
			}
		case strings.HasPrefix(key, "Sig[") && strings.HasSuffix(key, "].Name"):
			sigNames = append(sigNames, val)
		case strings.HasPrefix(key, "Sig[") && strings.HasSuffix(key, "].Value"):
			sigValues = append(sigValues, val)
		case key == "ReportIdentifier" || key == "DynamicSig[0].Name" ||
			key == "LibSign32" || key == "CabId":
			rep.Details[key] = val
		}
	}
	if rep.Type == "" && rep.App == "" {
		return nil, fmt.Errorf("dump: wer: no EventType or AppName found")
	}
	for i, n := range sigNames {
		name := n
		if i < len(sigValues) {
			name += " " + sigValues[i]
		}
		rep.Details[fmt.Sprintf("sig%d", i)] = name
	}
	if rep.PID == 0 {
		rep.PID = werInt(data, "PID")
	}
	rep.Summary = "windows error report"
	if rep.Type != "" {
		rep.Summary += " (" + rep.Type + ")"
	}
	if rep.App != "" {
		rep.Summary += " — " + rep.App
	}
	return rep, nil
}

// werInt scans a whole-file key for an integer value.
func werInt(data []byte, key string) int {
	idx := bytes.Index(data, []byte("\n"+key+"="))
	if idx < 0 {
		if !bytes.HasPrefix(data, []byte(key+"=")) {
			return 0
		}
		idx = -1
	}
	rest := data[idx+1:]
	end := bytes.IndexAny(rest, "\r\n")
	if end < 0 {
		end = len(rest)
	}
	n, err := strconv.Atoi(string(rest[len(key)+1 : end]))
	if err != nil {
		return 0
	}
	return n
}

// filetimeUTC converts a Windows FILETIME (100ns ticks since 1601) into an
// RFC 3339 UTC timestamp. Out-of-range values are reported as unreadable.
func filetimeUTC(s string) (string, bool) {
	ticks, err := strconv.ParseInt(s, 10, 64)
	if err != nil || ticks <= 0 {
		return "", false
	}
	const epochDiff = 11644473600 // seconds between 1601 and 1970
	sec := ticks/10_000_000 - epochDiff
	// Clamp to a sane window (1970..9999) instead of trusting the input.
	if sec < 0 || sec > 253402300799 {
		return "", false
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339), true
}
