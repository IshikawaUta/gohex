package hex

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IshikawaUta/gohex/internal/core"
	"github.com/IshikawaUta/gohex/internal/encoding"
)

func TestParseHexPatternForms(t *testing.T) {
	p, err := ParseHexPattern("4D 5A 90 00")
	if err != nil || p.Len() != 4 || p.kind != patExact {
		t.Fatalf("spaced: len=%d kind=%d err=%v", p.Len(), p.kind, err)
	}
	if p.Display() != "4D 5A 90 00" {
		t.Fatalf("display = %q", p.Display())
	}
	p, err = ParseHexPattern("4D5A9000")
	if err != nil || p.Len() != 4 || p.kind != patExact {
		t.Fatalf("compact: len=%d kind=%d err=%v", p.Len(), p.kind, err)
	}
	p, err = ParseHexPattern("4D ? 5A")
	if err != nil || p.Len() != 3 || p.kind != patMasked {
		t.Fatalf("wildcard: len=%d kind=%d err=%v", p.Len(), p.kind, err)
	}
	if p.Display() != "4D ?? 5A" {
		t.Fatalf("wildcard display = %q", p.Display())
	}
	p, err = ParseHexPattern("4? ?F")
	if err != nil || p.kind != patMasked {
		t.Fatalf("nibble: kind=%d err=%v", p.kind, err)
	}
	if p.Display() != "4? ?F" {
		t.Fatalf("nibble display = %q", p.Display())
	}
	p, err = ParseHexPattern("4* 5A *")
	if err != nil || p.Len() != 3 {
		t.Fatalf("star form: %v, %v", p, err)
	}
	for _, bad := range []string{"", "4", "ZZ", "4G", "123", "?4X"} {
		if _, err := ParseHexPattern(bad); err == nil {
			t.Errorf("ParseHexPattern(%q) should fail", bad)
		}
	}
	if _, err := ParseHexPattern("4M"); err == nil {
		t.Error("invalid digits should fail")
	}
}

func TestFindAllExactAcrossWindows(t *testing.T) {
	// Build a buffer larger than searchWindow with hits straddling the
	// window boundary on purpose.
	size := searchWindow + 1000
	data := bytes.Repeat([]byte{0x11}, size)
	needle := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	positions := []int{10, searchWindow - 3, searchWindow + 1, searchWindow + 500, size - 4}
	for _, pos := range positions {
		copy(data[pos:], needle)
	}
	d := newDocFrom(t, data)
	p, err := ParseHexPattern("DE AD BE EF")
	if err != nil {
		t.Fatal(err)
	}
	hits, err := FindAll(d, p, 0, d.Size(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != len(positions) {
		t.Fatalf("hits = %d, want %d: %v", len(hits), len(positions), hits)
	}
	for i, pos := range positions {
		if hits[i].Start != int64(pos) {
			t.Errorf("hit %d at %d, want %d", i, hits[i].Start, pos)
		}
		if hits[i].Length != 4 {
			t.Errorf("hit %d len %d", i, hits[i].Length)
		}
	}
	// max limit
	hits, err = FindAll(d, p, 0, d.Size(), 2)
	if err != nil || len(hits) != 2 {
		t.Fatalf("max limit: %d hits, %v", len(hits), err)
	}
	// range restriction
	hits, err = FindAll(d, p, 100, searchWindow, 0)
	if err != nil || len(hits) != 1 || hits[0].Start != int64(searchWindow-3) {
		t.Fatalf("range: %v, %v", hits, err)
	}
}

func TestFindNextPrev(t *testing.T) {
	data := []byte("abcXXdefXXghi")
	d := newDocFrom(t, data)
	p, _ := ParseHexPattern("58 58") // "XX"

	m, err := FindNext(d, p, 0)
	if err != nil || m == nil || m.Start != 3 {
		t.Fatalf("next from 0 = %v, %v", m, err)
	}
	m, err = FindNext(d, p, 4)
	if err != nil || m == nil || m.Start != 8 {
		t.Fatalf("next from 4 = %v, %v", m, err)
	}
	m, err = FindNext(d, p, 13)
	if err != nil || m != nil {
		t.Fatalf("next past end = %v, %v", m, err)
	}

	m, err = FindPrev(d, p, 13, 0)
	if err != nil || m == nil || m.Start != 8 {
		t.Fatalf("prev from 13 = %v, %v", m, err)
	}
	m, err = FindPrev(d, p, 8, 0)
	if err != nil || m == nil || m.Start != 3 {
		t.Fatalf("prev from 8 = %v, %v", m, err)
	}
	m, err = FindPrev(d, p, 3, 0)
	if err != nil || m != nil {
		t.Fatalf("prev before first = %v, %v", m, err)
	}
	_ = m
	m, err = FindPrev(d, p, 3, 4)
	if err != nil || m != nil {
		t.Fatalf("prev with from>start = %v, %v", m, err)
	}
}

func TestFindPrevAcrossWindows(t *testing.T) {
	size := searchWindow + 2000
	data := bytes.Repeat([]byte{0x22}, size)
	needle := []byte{0xFE, 0xED}
	copy(data[searchWindow+1500:], needle)
	d := newDocFrom(t, data)
	p, _ := ParseHexPattern("FE ED")
	m, err := FindPrev(d, p, d.Size(), 0)
	if err != nil || m == nil || m.Start != int64(searchWindow+1500) {
		t.Fatalf("prev across windows = %v, %v", m, err)
	}
	// No hit before the needle.
	m, err = FindPrev(d, p, searchWindow, 0)
	if err != nil || m != nil {
		t.Fatalf("prev empty region = %v, %v", m, err)
	}
}

func TestWildcardMatching(t *testing.T) {
	data := []byte{0x4D, 0x00, 0x90, 0x00, 0x4D, 0x5A, 0x90, 0x00}
	d := newDocFrom(t, data)
	p, _ := ParseHexPattern("4D ? 90")
	hits, err := FindAll(d, p, 0, d.Size(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 || hits[0].Start != 0 || hits[1].Start != 4 {
		t.Fatalf("masked hits = %v", hits)
	}
}

func TestTextPatternCaseFold(t *testing.T) {
	data := []byte("Hello WORLD hello wOrLd")
	d := newDocFrom(t, data)
	p, err := NewTextPattern("hello", bincoding.ASCII, true)
	if err != nil {
		t.Fatal(err)
	}
	hits, err := FindAll(d, p, 0, d.Size(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 { // "Hello" and "hello"; "WORLD"/"wOrLd" are not "hello"
		t.Fatalf("case-fold hits = %d: %v", len(hits), hits)
	}
	if _, err := NewTextPattern("", bincoding.ASCII, false); err == nil {
		t.Fatal("empty text should fail")
	}
	// UTF-16 text pattern
	p16, err := NewTextPattern("hi", bincoding.UTF16LE, false)
	if err != nil {
		t.Fatal(err)
	}
	d16 := newDocFrom(t, []byte("x\x00h\x00i\x00y\x00"))
	hits, err = FindAll(d16, p16, 0, d16.Size(), 0)
	if err != nil || len(hits) != 1 || hits[0].Start != 2 {
		t.Fatalf("utf16 hits = %v, %v", hits, err)
	}
}

func TestRegexPattern(t *testing.T) {
	data := []byte("id=42; id=7; id=1000;\x00tail")
	d := newDocFrom(t, data)
	p, err := NewRegexPattern(`id=\d+`)
	if err != nil {
		t.Fatal(err)
	}
	hits, err := FindAll(d, p, 0, d.Size(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 3 {
		t.Fatalf("regex hits = %v", hits)
	}
	if string(data[hits[2].Start:hits[2].Start+hits[2].Length]) != "id=1000" {
		t.Fatalf("third hit = %q", data[hits[2].Start:hits[2].Start+hits[2].Length])
	}
	// Reverse search
	m, err := FindPrev(d, p, d.Size(), 0)
	if err != nil || m == nil || m.Start != int64(bytes.LastIndex(data, []byte("id=1000"))) {
		t.Fatalf("regex prev = %v, %v", m, err)
	}
	if _, err := NewRegexPattern("("); err == nil {
		t.Fatal("invalid regex should fail")
	}
	if _, err := NewRegexPattern(""); err == nil {
		t.Fatal("empty regex should fail")
	}
	pLen := p.Len()
	if pLen != -1 {
		t.Fatalf("regex Len = %d", pLen)
	}
}

func TestRegexAcrossWindow(t *testing.T) {
	// A regex hit that starts just before the first window boundary must be
	// found via the overlap region.
	size := searchWindow + 100
	data := bytes.Repeat([]byte{0x41}, size)
	marker := "SEQ:" + strings.Repeat("Z", 50)
	copy(data[searchWindow-10:], marker)
	d := newDocFrom(t, data)
	p, err := NewRegexPattern(`SEQ:Z+`)
	if err != nil {
		t.Fatal(err)
	}
	hits, err := FindAll(d, p, 0, d.Size(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Start != int64(searchWindow-10) {
		t.Fatalf("cross-window regex hits = %v", hits)
	}
}

func TestReplaceAll(t *testing.T) {
	cases := []struct {
		name  string
		base  string
		pat   string
		repl  string
		want  string
		count int
	}{
		{"equal", "aXbXc", "58", "yy", "ayybyyc", 2},
		{"shorter", "aXXb", "58 58", "Y", "aYb", 1},
		{"longer", "aXb", "58", "LONG", "aLONGb", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDocFrom(t, []byte(c.base))
			p, err := ParseHexPattern(c.pat)
			if err != nil {
				t.Fatal(err)
			}
			n, err := d.ReplaceAll(p, []byte(c.repl), 0)
			if err != nil {
				t.Fatal(err)
			}
			if n != c.count {
				t.Fatalf("count = %d, want %d", n, c.count)
			}
			got, _ := d.ReadCopy(0, d.Size())
			if string(got) != c.want {
				t.Fatalf("result = %q, want %q", got, c.want)
			}
			// The whole replace-all is undoable step by step.
			for {
				if _, err := d.Undo(); err != nil {
					break
				}
			}
			got, _ = d.ReadCopy(0, d.Size())
			if string(got) != c.base {
				t.Fatalf("after undo = %q, want %q", got, c.base)
			}
		})
	}
}

func TestReplaceAllRespectsMax(t *testing.T) {
	d := newDocFrom(t, []byte("aaaa"))
	p, _ := ParseHexPattern("61")
	n, err := d.ReplaceAll(p, []byte("b"), 2)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestFindAllErrors(t *testing.T) {
	d := newDocFrom(t, []byte("abc"))
	if _, err := FindAll(d, nil, 0, 3, 0); err == nil {
		t.Error("nil pattern should fail")
	}
	if _, err := FindNext(d, nil, 0); err == nil {
		t.Error("nil pattern should fail")
	}
	if _, err := FindPrev(d, nil, 3, 0); err == nil {
		t.Error("nil pattern should fail")
	}
	// Empty range
	p, _ := ParseHexPattern("61")
	hits, err := FindAll(d, p, 3, 3, 0)
	if err != nil || len(hits) != 0 {
		t.Errorf("empty range = %v, %v", hits, err)
	}
	hits, err = FindAll(d, p, 0, -1, 0) // to<0 → clamp to size
	if err != nil || len(hits) != 1 {
		t.Errorf("negative to = %v, %v", hits, err)
	}
}

func TestStreamConformanceOnRawSource(t *testing.T) {
	// Search directly over a core.Source (no Document) — used by the CLI.
	p := writeTempDoc(t, bytes.Repeat([]byte{0xAB, 0xCD}, 100))
	src, err := core.OpenFile(p)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	pat, _ := ParseHexPattern("AB CD")
	hits, err := FindAll(src, pat, 0, src.Size(), 3)
	if err != nil || len(hits) != 3 || hits[0].Start != 0 {
		t.Fatalf("source search = %v, %v", hits, err)
	}
	if _, ok := interface{}(src).(Stream); !ok {
		t.Fatal("core.Source must satisfy Stream")
	}
}

func writeTempDoc(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.bin")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
