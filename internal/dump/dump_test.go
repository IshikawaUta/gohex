package dump

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseIPS(t *testing.T) {
	rep, err := Parse(fixture(t, "macos/crash.ips"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rep.Source != "macos" || rep.Format != "ips" {
		t.Fatalf("source/format = %s/%s", rep.Source, rep.Format)
	}
	if rep.App != "GoHex" || rep.Version != "1.2.3" {
		t.Fatalf("app/version = %q/%q", rep.App, rep.Version)
	}
	if rep.Type != "crash (bug_type 309)" || rep.Details["bugType"] != "309" {
		t.Fatalf("type = %q details = %v", rep.Type, rep.Details)
	}
	if rep.PID != 4242 {
		t.Fatalf("pid = %d", rep.PID)
	}
	if rep.Details["signal"] != "11" || rep.Details["exceptionCode"] != "1" {
		t.Fatalf("exception = %v", rep.Details)
	}
	if rep.Timestamp != "2026-10-10 12:00:00.00 +0200" {
		t.Fatalf("timestamp = %q", rep.Timestamp)
	}
	// faultingThread=1 has two frames.
	if rep.Frames != 2 || len(rep.TopFrames) != 2 {
		t.Fatalf("frames = %d top = %v", rep.Frames, rep.TopFrames)
	}
	if !strings.Contains(rep.TopFrames[0], "-[AppDelegate applicationDidFinishLaunching:]+0x") {
		t.Fatalf("frame0 = %q", rep.TopFrames[0])
	}
	if !strings.Contains(rep.Summary, "signal 11") {
		t.Fatalf("summary = %q", rep.Summary)
	}
}

func TestParseIPSiOS(t *testing.T) {
	ips := `{"app_name":"Safari","timestamp":"2026-10-10 12:00:00.00 +0000","bug_type":"309"}
{"procName":"Safari","pid":7,"os_version":"iOS 17.2","threads":[{"frames":[{"imageOffset":100,"symbol":"main","imageIndex":0}]}]}
`
	rep, err := Parse([]byte(ips))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rep.Source != "ios" || rep.App != "Safari" || rep.Frames != 1 {
		t.Fatalf("rep = %+v", rep)
	}
}

func TestParseTombstone(t *testing.T) {
	rep, err := Parse(fixture(t, "mobile/tombstone.txt"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rep.Source != "android" || rep.Format != "tombstone" {
		t.Fatalf("source/format = %s/%s", rep.Source, rep.Format)
	}
	if rep.App != "com.example.forensics" {
		t.Fatalf("app = %q", rep.App)
	}
	if rep.PID != 1234 || rep.TID != 1234 {
		t.Fatalf("pid/tid = %d/%d", rep.PID, rep.TID)
	}
	if rep.Type != "SIGSEGV" {
		t.Fatalf("type = %q", rep.Type)
	}
	if rep.Details["code"] != "1 (SEGV_MAPERR)" ||
		rep.Details["faultAddr"] != "0x0000000000000000" {
		t.Fatalf("details = %v", rep.Details)
	}
	if !strings.Contains(rep.Details["fingerprint"], "sdk_gphone64") {
		t.Fatalf("fingerprint = %q", rep.Details["fingerprint"])
	}
	if rep.Frames != 3 || len(rep.TopFrames) != 3 {
		t.Fatalf("frames = %d top = %v", rep.Frames, rep.TopFrames)
	}
	if !strings.Contains(rep.TopFrames[0], "libc.so (memcpy+188)") {
		t.Fatalf("frame0 = %q", rep.TopFrames[0])
	}
	if rep.Timestamp != "2026-10-10 12:00:00.123456789+0000" {
		t.Fatalf("timestamp = %q", rep.Timestamp)
	}
}

func TestParseWER(t *testing.T) {
	rep, err := Parse(fixture(t, "windows/report.wer"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rep.Source != "windows" || rep.Format != "wer" {
		t.Fatalf("source/format = %s/%s", rep.Source, rep.Format)
	}
	if rep.Type != "APPCRASH" || rep.App != "GoHex.exe" || rep.Version != "1.2.3.0" {
		t.Fatalf("type/app/version = %q/%q/%q", rep.Type, rep.App, rep.Version)
	}
	if rep.Timestamp != "2026-01-01T00:00:00Z" {
		t.Fatalf("timestamp = %q", rep.Timestamp)
	}
	if rep.PID != 999 {
		t.Fatalf("pid = %d", rep.PID)
	}
	if rep.Details["sig0"] != "Exception Code c0000005" {
		t.Fatalf("sig0 = %q", rep.Details["sig0"])
	}
	if !strings.Contains(rep.Summary, "APPCRASH") {
		t.Fatalf("summary = %q", rep.Summary)
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Fatal("empty input should fail")
	}
	if _, err := Parse(make([]byte, MaxReportSize+1)); err == nil {
		t.Fatal("oversize input should fail")
	}
	if _, err := Parse([]byte("just some plain text\nnot a report")); !errors.Is(err, ErrUnrecognized) {
		t.Fatalf("want ErrUnrecognized, got %v", err)
	}
	if _, err := Parse([]byte("{not json\n{}")); err == nil {
		t.Fatal("malformed ips should fail")
	}
	// A tombstone banner with no usable content is rejected, not guessed.
	if _, err := Parse([]byte("*** *** *** ***\nsomething else entirely")); err == nil {
		t.Fatal("banner-only input should fail")
	}
	if _, err := Parse([]byte("EventType=\n")); err == nil {
		t.Fatal("empty wer should fail")
	}
}

func TestFiletimeOutOfRange(t *testing.T) {
	if _, ok := filetimeUTC("99999999999999999999"); ok {
		t.Fatal("garbage should be rejected")
	}
	if _, ok := filetimeUTC("-5"); ok {
		t.Fatal("negative should be rejected")
	}
	if _, ok := filetimeUTC("not-a-number"); ok {
		t.Fatal("non-numeric should be rejected")
	}
}
