package hex

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/IshikawaUta/gohex/internal/core"
	bincoding "github.com/IshikawaUta/gohex/internal/encoding" // package bincoding
)

// Stream is the minimal read interface the search engine needs; both
// core.Source and *Document satisfy it, so search works on raw files as well
// as on edited documents.
type Stream interface {
	io.ReaderAt
	Size() int64
}

// Match is one search hit.
type Match struct {
	Start  int64 `json:"start"`
	Length int64 `json:"length"`
}

// searchWindow is the streaming window size for pattern scans. Matches are
// found per window with an overlap of the pattern length minus one, so no
// hit can straddle a window boundary unnoticed.
const searchWindow = 4 << 20 // 4 MiB

// regexOverlap is the trailing lookahead kept for regex windows; matches
// longer than this may be missed on files that do not fit in memory (a
// documented, conservative bound — realistic forensic regexes are far
// shorter).
const regexOverlap = 1 << 20 // 1 MiB

type patKind uint8

const (
	patExact patKind = iota
	patMasked
	patRegex
)

// Pattern is a compiled search pattern: exact or nibble-masked byte sequence
// or a RE2 regular expression.
type Pattern struct {
	kind     patKind
	bytes    []byte
	mask     []byte // nil for exact
	re       *regexp.Regexp
	caseFold bool
	display  string
}

// Display returns a human-readable form of the pattern for dialogs/logs.
func (p *Pattern) Display() string { return p.display }

// Len returns the fixed pattern length, or -1 for regex patterns.
func (p *Pattern) Len() int {
	if p.kind == patRegex {
		return -1
	}
	return len(p.bytes)
}

// overlap returns how many bytes beyond a segment must be read to catch a
// match starting inside it.
func (p *Pattern) overlap() int {
	if p.kind == patRegex {
		return regexOverlap
	}
	return len(p.bytes) - 1
}

// ParseHexPattern compiles a hex pattern with optional nibble wildcards:
//
//	4D 5A 90 00   exact bytes
//	4D5A9000      compact form
//	4D ? 5A ??    '?' or '*' marks a fully unknown byte
//	4? ?F         partial-byte wildcards (only the known nibble is compared)
//
// Whitespace, commas, colons and dashes are ignored as separators.
func ParseHexPattern(s string) (*Pattern, error) {
	fields := splitHexFields(s)
	if len(fields) == 0 {
		return nil, fmt.Errorf("hex: empty pattern")
	}
	var bs, ms []byte
	masked := false
	for _, f := range fields {
		switch {
		case len(f) == 1 && (f[0] == '?' || f[0] == '*'):
			bs = append(bs, 0)
			ms = append(ms, 0x00)
			masked = true
		case len(f) == 2:
			b, m, err := hexPair(f[0], f[1])
			if err != nil {
				return nil, err
			}
			bs = append(bs, b)
			ms = append(ms, m)
			if m != 0xFF {
				masked = true
			}
		default:
			return nil, fmt.Errorf("hex: pattern token %q must be 1-2 hex/wildcard characters", f)
		}
	}
	p := &Pattern{bytes: bs, display: bincoding.SpacedHex(bs)}
	if masked {
		p.kind = patMasked
		p.mask = ms
		p.display = maskedHexDisplay(bs, ms)
	} else {
		p.kind = patExact
	}
	return p, nil
}

func splitHexFields(s string) []string {
	var out []string
	var cur []byte
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case ' ', '\t', '\n', '\r', ',', ':', '-', '_':
			flush()
		default:
			cur = append(cur, c)
		}
	}
	flush()
	// A long hex run without separators ("4D5A9000") is split into byte pairs.
	var expanded []string
	for _, f := range out {
		allHex := true
		for i := 0; i < len(f); i++ {
			if !isHexChar(f[i]) && f[i] != '?' && f[i] != '*' {
				allHex = false
				break
			}
		}
		if allHex && len(f) > 2 && len(f)%2 == 0 {
			for j := 0; j < len(f); j += 2 {
				expanded = append(expanded, f[j:j+2])
			}
		} else {
			expanded = append(expanded, f)
		}
	}
	return expanded
}

func isHexChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexPair(hi, lo byte) (b, mask byte, err error) {
	if hi == '?' || hi == '*' {
		if lo == '?' || lo == '*' {
			return 0, 0x00, nil
		}
		if !isHexChar(lo) {
			return 0, 0, fmt.Errorf("hex: invalid wildcard pair %q%q", hi, lo)
		}
		v, _ := hexNibble(lo)
		return v, 0x0F, nil
	}
	if lo == '?' || lo == '*' {
		if !isHexChar(hi) {
			return 0, 0, fmt.Errorf("hex: invalid wildcard pair %q%q", hi, lo)
		}
		v, _ := hexNibble(hi)
		return v << 4, 0xF0, nil
	}
	if !isHexChar(hi) || !isHexChar(lo) {
		return 0, 0, fmt.Errorf("hex: invalid hex pair %q%q", hi, lo)
	}
	h, _ := hexNibble(hi)
	l, _ := hexNibble(lo)
	return h<<4 | l, 0xFF, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("hex: invalid nibble %q", c)
}

func maskedHexDisplay(b, m []byte) string {
	s := ""
	for i := range b {
		if i > 0 {
			s += " "
		}
		switch m[i] {
		case 0x00:
			s += "??"
		case 0xF0:
			s += fmt.Sprintf("%X?", b[i]>>4)
		case 0x0F:
			s += fmt.Sprintf("?%X", b[i]&0x0F)
		default:
			s += fmt.Sprintf("%02X", b[i])
		}
	}
	return s
}

// NewTextPattern compiles a literal text pattern encoded with enc. When
// caseFold is true an ASCII-case-insensitive match is performed (safe for
// UTF-8 and single-byte encodings: ASCII case bytes never occur inside
// multi-byte sequences).
func NewTextPattern(text string, enc bincoding.Encoding, caseFold bool) (*Pattern, error) {
	if text == "" {
		return nil, fmt.Errorf("hex: empty text pattern")
	}
	b := bincoding.Encode(enc, text)
	if len(b) == 0 {
		return nil, fmt.Errorf("hex: pattern encodes to zero bytes")
	}
	p := &Pattern{kind: patExact, bytes: b, caseFold: caseFold, display: text}
	if caseFold {
		p.kind = patMasked
		p.mask = asciiFoldMask(b)
	}
	return p, nil
}

// asciiFoldMask builds a mask that ignores the ASCII case bit (0x20) on
// alphabetic bytes and requires every other bit.
func asciiFoldMask(b []byte) []byte {
	m := make([]byte, len(b))
	for i, c := range b {
		m[i] = 0xFF
		if isASCIILetter(c) {
			m[i] &^= 0x20 // ignore the ASCII case bit
		}
	}
	return m
}

func isASCIILetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// NewRegexPattern compiles a RE2 regular expression searched over the raw
// byte view of the document (use (?i) for case-insensitivity — RE2 cannot
// backtrack exponentially, so patterns are safe against ReDoS).
func NewRegexPattern(expr string) (*Pattern, error) {
	if expr == "" {
		return nil, fmt.Errorf("hex: empty regex")
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("hex: regex: %w", err)
	}
	return &Pattern{kind: patRegex, re: re, display: expr}, nil
}

// FindAll scans [from, to) for up to max matches (max <= 0 means no limit).
// Matches are returned in ascending order.
func FindAll(s Stream, p *Pattern, from, to int64, max int) ([]Match, error) {
	if p == nil {
		return nil, fmt.Errorf("hex: nil pattern")
	}
	size := s.Size()
	if from < 0 {
		from = 0
	}
	if to < 0 || to > size {
		to = size
	}
	if from >= to {
		return nil, nil
	}
	if p.kind != patRegex && len(p.bytes) == 0 {
		return nil, nil
	}
	var out []Match
	seg := from
	ov := p.overlap()
	for seg < to {
		segEnd := seg + searchWindow
		if segEnd > to {
			segEnd = to
		}
		readEnd := segEnd + int64(ov)
		if readEnd > size {
			readEnd = size
		}
		buf := make([]byte, readEnd-seg)
		if _, err := readFullAt(s, buf, seg); err != nil {
			return out, fmt.Errorf("hex: search read at %#x: %w", seg, err)
		}
		hits := scanWindow(p, buf, seg, segEnd, readEnd >= size)
		out = append(out, hits...)
		if max > 0 && len(out) >= max {
			return out[:max], nil
		}
		if segEnd >= to {
			break
		}
		seg = segEnd
	}
	return out, nil
}

// FindNext returns the first match at or after from, or nil.
func FindNext(s Stream, p *Pattern, from int64) (*Match, error) {
	hits, err := FindAll(s, p, from, s.Size(), 1)
	if err != nil || len(hits) == 0 {
		return nil, err
	}
	return &hits[0], nil
}

// FindPrev returns the last match starting strictly before before and at or
// after from, or nil.
func FindPrev(s Stream, p *Pattern, before, from int64) (*Match, error) {
	if p == nil {
		return nil, fmt.Errorf("hex: nil pattern")
	}
	size := s.Size()
	if before > size {
		before = size
	}
	if from < 0 {
		from = 0
	}
	if from >= before {
		return nil, nil
	}
	ov := p.overlap()
	end := before
	for end > from {
		start := end - searchWindow
		if start < from {
			start = from
		}
		readEnd := end + int64(ov)
		if readEnd > size {
			readEnd = size
		}
		buf := make([]byte, readEnd-start)
		if _, err := readFullAt(s, buf, start); err != nil {
			return nil, fmt.Errorf("hex: reverse search read at %#x: %w", start, err)
		}
		// Accept matches that start inside [start, end): the scan helper
		// filters by segment end; pass `end` as that bound.
		hits := scanWindow(p, buf, start, end, readEnd >= size)
		if len(hits) > 0 {
			last := hits[len(hits)-1]
			if last.Start < before {
				return &last, nil
			}
		}
		if start <= from {
			break
		}
		end = start
	}
	return nil, nil
}

// scanWindow searches buf (whose first byte lives at absolute offset base)
// and returns matches whose start lies in [base, segEnd).
func scanWindow(p *Pattern, buf []byte, base, segEnd int64, atEOF bool) []Match {
	var out []Match
	accept := func(start, length int) {
		abs := base + int64(start)
		if abs >= segEnd {
			return
		}
		out = append(out, Match{Start: abs, Length: int64(length)})
	}
	switch p.kind {
	case patExact:
		for i := 0; i+len(p.bytes) <= len(buf); {
			j := bytes.Index(buf[i:], p.bytes)
			if j < 0 {
				break
			}
			abs := base + int64(i+j)
			if abs >= segEnd {
				break
			}
			accept(i+j, len(p.bytes))
			i += j + 1
		}
	case patMasked:
		pl := len(p.bytes)
		for i := 0; i+pl <= len(buf); i++ {
			ok := true
			for k := 0; k < pl; k++ {
				if buf[i+k]&p.mask[k] != p.bytes[k]&p.mask[k] {
					ok = false
					break
				}
			}
			if ok {
				accept(i, pl)
			}
		}
	case patRegex:
		if !atEOF && len(buf) > regexOverlap {
			// Only accept matches ending before the raw tail so a truncated
			// regex match is never reported.
			search := buf[:len(buf)-regexOverlap]
			for _, loc := range p.re.FindAllIndex(search, -1) {
				accept(loc[0], loc[1]-loc[0])
			}
		} else {
			for _, loc := range p.re.FindAllIndex(buf, -1) {
				accept(loc[0], loc[1]-loc[0])
			}
		}
	}
	return out
}

func readFullAt(s Stream, p []byte, off int64) (int, error) {
	n := 0
	for n < len(p) {
		got, err := s.ReadAt(p[n:], off+int64(n))
		n += got
		if err != nil {
			if errors.Is(err, io.EOF) && n == len(p) {
				return n, nil
			}
			if errors.Is(err, io.EOF) && n > 0 && n < len(p) && off+int64(n) >= s.Size() {
				return n, nil
			}
			return n, err
		}
		if got == 0 {
			return n, io.ErrUnexpectedEOF
		}
	}
	return n, nil
}

// ReplaceAll replaces every match of p in s with the bytes produced by repl.
// It returns the number of replacements. The target must be a *Document so
// each replacement becomes an undoable edit; callers in the GUI use
// Document.ReplaceWithConfirm instead, which asks before bulk edits.
func (d *Document) ReplaceAll(p *Pattern, repl []byte, max int) (int, error) {
	hits, err := FindAll(d, p, 0, d.Size(), max)
	if err != nil {
		return 0, err
	}
	// Apply back-to-front so earlier offsets stay valid.
	n := 0
	for i := len(hits) - 1; i >= 0; i-- {
		h := hits[i]
		rl := int64(len(repl))
		switch {
		case rl == h.Length:
			if err := d.Overwrite(h.Start, repl); err != nil {
				return n, err
			}
		case rl < h.Length:
			if err := d.Overwrite(h.Start, repl); err != nil {
				return n, err
			}
			if err := d.Delete(h.Start+rl, h.Length-rl); err != nil {
				return n, err
			}
		default: // replacement longer than the match: overwrite the match, then insert the tail
			if err := d.Overwrite(h.Start, repl[:h.Length]); err != nil {
				return n, err
			}
			if err := d.Insert(h.Start+h.Length, repl[h.Length:]); err != nil {
				return n, err
			}
		}
		n++
	}
	return n, nil
}

// compile-time conformance
var (
	_ Stream = (core.Source)(nil)
	_ Stream = (*Document)(nil)
)
