package dump

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// isIPS sniffs a macOS/iOS crash report: a JSON header line containing
// "bug_type", a newline, then the big JSON body.
func isIPS(data []byte) bool {
	if len(data) == 0 || data[0] != '{' {
		return false
	}
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		return false
	}
	first := data[:nl]
	if !bytes.Contains(first, []byte(`"bug_type"`)) {
		return false
	}
	rest := bytes.TrimLeft(data[nl+1:], "\r\n")
	return len(rest) > 0 && rest[0] == '{'
}

func parseIPS(data []byte) (*Report, error) {
	nl := bytes.IndexByte(data, '\n')
	var header, body map[string]any
	if err := json.Unmarshal(data[:nl], &header); err != nil {
		return nil, fmt.Errorf("dump: ips header: %w", err)
	}
	rest := bytes.TrimLeft(data[nl+1:], "\r\n")
	if err := json.Unmarshal(rest, &body); err != nil {
		return nil, fmt.Errorf("dump: ips body: %w", err)
	}

	rep := &Report{
		Source:  "macos",
		Format:  "ips",
		Details: map[string]string{},
	}
	if bytes.Contains(head(data, MaxReportSize), []byte("iOS ")) ||
		bytes.Contains(head(data, MaxReportSize), []byte("iPhone OS ")) {
		rep.Source = "ios"
	}

	rep.App = jstr(header, "app_name")
	if rep.App == "" {
		rep.App = jstr(body, "procName")
	}
	if rep.App == "" {
		rep.App = baseName(jstr(body, "procPath"))
	}
	rep.Timestamp = jstr(header, "timestamp")
	rep.Version = jstr(body, "app_version")
	if rep.Version == "" {
		if bi, ok := body["bundleInfo"].(map[string]any); ok {
			rep.Version = jstr(bi, "CFBundleShortVersionString")
		}
	}
	rep.PID = jint(header, "pid", "proc_id")
	if rep.PID == 0 {
		rep.PID = jint(body, "pid")
	}
	rep.TID = jint(body, "tid")

	if bt := jstr(header, "bug_type"); bt != "" {
		rep.Type = bt
		if bt == "309" {
			rep.Type = "crash (bug_type 309)"
		}
		rep.Details["bugType"] = bt
	}
	if os := jstr(body, "os_version"); os != "" {
		rep.Details["osVersion"] = os
	}
	if path := jstr(body, "procPath"); path != "" {
		rep.Details["procPath"] = path
	}

	// Exception / termination describe why the process died.
	if ex, ok := body["exception"].(map[string]any); ok {
		if sig := jnum(ex, "signal"); sig != 0 {
			rep.Details["signal"] = strconv.Itoa(sig)
		}
		if code := jnum(ex, "code"); code != 0 {
			rep.Details["exceptionCode"] = strconv.Itoa(code)
		}
	}
	if term, ok := body["termination"].(map[string]any); ok {
		if ind := jstr(term, "indicator"); ind != "" {
			rep.Details["termination"] = ind
		}
	}

	// Frame counts come from the faulting thread when present.
	threads, _ := body["threads"].([]any)
	fault := jint(body, "faultingThread")
	frames := threadFrames(threads, fault)
	rep.Frames = len(frames)
	rep.TopFrames = capFrames(frames)

	rep.Summary = summarizeIPS(rep)
	return rep, nil
}

// threadFrames returns the frame renderings of threads[i]; an out-of-range
// index falls back to thread 0, and a missing thread list yields nothing.
func threadFrames(threads []any, i int) []string {
	if len(threads) == 0 {
		return nil
	}
	if i < 0 || i >= len(threads) {
		i = 0
	}
	th, ok := threads[i].(map[string]any)
	if !ok {
		return nil
	}
	raw, _ := th["frames"].([]any)
	out := make([]string, 0, len(raw))
	for _, f := range raw {
		m, ok := f.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, renderIPSFrame(m))
	}
	return out
}

func renderIPSFrame(f map[string]any) string {
	sym := jstr(f, "symbol")
	off := jnum(f, "imageOffset")
	if sym != "" {
		return fmt.Sprintf("%s+0x%x", sym, off)
	}
	return fmt.Sprintf("imageIndex=%s+0x%x", jstr(f, "imageIndex"), off)
}

// capFrames keeps at most the first 5 frames of a stack.
func capFrames(frames []string) []string {
	if len(frames) > 5 {
		return frames[:5]
	}
	return frames
}

func summarizeIPS(rep *Report) string {
	s := "crash report"
	if rep.Type != "" {
		s = rep.Type + " report"
	}
	if rep.App != "" {
		s += " — " + rep.App
	}
	if sig, ok := rep.Details["signal"]; ok {
		s += fmt.Sprintf(", signal %s", sig)
	}
	return s
}

// jstr looks up the first present string value among keys.
func jstr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// jnum returns an int-valued JSON number (json decodes all numbers float64).
func jnum(m map[string]any, key string) int {
	v, ok := m[key].(float64)
	if !ok {
		return 0
	}
	return int(v)
}

func jint(m map[string]any, keys ...string) int {
	for _, k := range keys {
		if n := jnum(m, k); n != 0 {
			return n
		}
	}
	return 0
}

func baseName(p string) string {
	if p == "" {
		return ""
	}
	for i := len(p) - 1; i > 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
