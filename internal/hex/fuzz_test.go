package hex

import (
	"io"
	"testing"

	bincoding "github.com/IshikawaUta/gohex/internal/encoding"
)

// FuzzPatternCompile fuzzes the three pattern compilers Find uses (hex,
// text, regex). The compile step is where malformed user input surfaces;
// matching is exercised afterwards against an arbitrary haystack so a
// compiled pattern must also survive scanning.
func FuzzPatternCompile(f *testing.F) {
	f.Add("hex", "48 65 6c 6c 6f")
	f.Add("hex", "48 6? 6c **")
	f.Add("hex", "not hex at all")
	f.Add("hex", "")
	f.Add("text", "needle")
	f.Add("text", "")
	f.Add("regex", "^a+b.*$")
	f.Add("regex", "([")
	f.Add("regex", "(?i)Case")
	f.Add("bogus", "x")
	f.Fuzz(func(t *testing.T, mode, pattern string) {
		if len(pattern) > 4096 {
			t.Skip("pattern too long")
		}
		var (
			p   *Pattern
			err error
		)
		switch mode {
		case "hex":
			p, err = ParseHexPattern(pattern)
		case "text":
			p, err = NewTextPattern(pattern, bincoding.ASCII, false)
		case "regex":
			p, err = NewRegexPattern(pattern)
		default:
			return
		}
		if err != nil || p == nil {
			return
		}
		hay := &memStream{data: []byte("hello needle world " + pattern + "\x00\xffhello")}
		_, _ = FindAll(hay, p, 0, hay.Size(), 16)
		_, _ = FindNext(hay, p, 0)
		_, _ = FindPrev(hay, p, hay.Size(), 0)
	})
}

// memStream adapts a byte slice to the Stream interface Find* consume.
type memStream struct{ data []byte }

func (m *memStream) Size() int64 { return int64(len(m.data)) }
func (m *memStream) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
