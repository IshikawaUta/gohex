package dump

import (
	"os"
	"testing"
)

// FuzzDumpParse drives the crash-report dispatcher over arbitrary bytes. The
// three format sniffers (IPS, tombstone, WER) plus their parsers must only
// ever return a report or an error.
func FuzzDumpParse(f *testing.F) {
	for _, p := range []string{
		"testdata/macos/crash.ips",
		"testdata/mobile/tombstone.txt",
		"testdata/windows/report.wer",
	} {
		if data, err := os.ReadFile(p); err == nil {
			f.Add(data)
		}
	}
	f.Add([]byte{})                                     // empty
	f.Add([]byte("Exception Type:  EXC_BAD_ACCESS\n"))  // header-ish garbage
	f.Add([]byte("Abort message: 'not a tombstone'\n")) // Android-ish garbage
	f.Add([]byte("\x00\x01\x02\x03binary junk\x00"))    // binary garbage
	f.Add([]byte("{"))                                  // truncated JSON
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxReportSize {
			t.Skip("input larger than Parse accepts")
		}
		_, _ = Parse(data)
	})
}
