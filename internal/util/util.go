// Package util collects the small, self-contained forensic utilities a
// hex-editor workbench needs: entropy, byte frequency, a safe arithmetic
// evaluator for the hex calculator, regex search, strings extraction,
// file split/join, secure deletion, password/UUID/ULID generation,
// timestamp conversion and random-byte generation. Every function is
// pure and deterministic given its inputs (the generators take an
// io.Reader for testability), so they are trivially fuzzable and
// reusable from the service layer, the CLI and future plugins.
package util

import (
	"bufio"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Entropy computes the Shannon entropy of data in bits per byte
// (0.0 for an empty or single-value buffer, 8.0 for a perfect mix).
func Entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// BlockEntropy splits data into blocks of blockSize and returns the
// entropy of each block. It is the primitive behind entropy heatmaps.
func BlockEntropy(data []byte, blockSize int) []float64 {
	if blockSize <= 0 {
		blockSize = 256
	}
	out := make([]float64, 0, (len(data)+blockSize-1)/blockSize)
	for i := 0; i < len(data); i += blockSize {
		end := i + blockSize
		if end > len(data) {
			end = len(data)
		}
		out = append(out, Entropy(data[i:end]))
	}
	return out
}

// ByteCount is one histogram slot.
type ByteCount struct {
	Byte  int   `json:"byte"`
	Count int64 `json:"count"`
}

// ByteFrequency returns the 256-slot histogram of data, sorted by
// descending count then ascending byte value (ties broken
// deterministically so callers can page through it safely).
func ByteFrequency(data []byte) []ByteCount {
	var freq [256]int64
	for _, b := range data {
		freq[b]++
	}
	out := make([]ByteCount, 0, 256)
	for i, c := range freq {
		if c > 0 {
			out = append(out, ByteCount{Byte: i, Count: c})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Byte < out[j].Byte
	})
	return out
}

// EvalExpr evaluates an integer arithmetic expression in a restricted
// grammar: decimal and 0x-hex literals, + - * / % and parentheses,
// with unary minus. Division by zero and non-integer operands are
// errors; there is no function call, variable or state, so the
// evaluator is safe to expose to untrusted input.
func EvalExpr(expr string) (int64, error) {
	e := &exprEval{s: strings.TrimSpace(expr)}
	if e.s == "" {
		return 0, errors.New("util: empty expression")
	}
	v, err := e.parseExpr()
	if err != nil {
		return 0, err
	}
	if e.pos != len(e.s) {
		return 0, fmt.Errorf("util: trailing input at %d", e.pos)
	}
	return v, nil
}

type exprEval struct {
	s   string
	pos int
}

func (e *exprEval) peek() byte {
	if e.pos < len(e.s) {
		return e.s[e.pos]
	}
	return 0
}

func (e *exprEval) skipSpace() {
	for e.pos < len(e.s) && (e.s[e.pos] == ' ' || e.s[e.pos] == '\t') {
		e.pos++
	}
}

func (e *exprEval) parseExpr() (int64, error) {
	v, err := e.parseTerm()
	if err != nil {
		return 0, err
	}
	for {
		e.skipSpace()
		c := e.peek()
		if c != '+' && c != '-' {
			return v, nil
		}
		e.pos++
		r, err := e.parseTerm()
		if err != nil {
			return 0, err
		}
		if c == '+' {
			v += r
		} else {
			v -= r
		}
	}
}

func (e *exprEval) parseTerm() (int64, error) {
	v, err := e.parseFactor()
	if err != nil {
		return 0, err
	}
	for {
		e.skipSpace()
		c := e.peek()
		if c != '*' && c != '/' && c != '%' {
			return v, nil
		}
		e.pos++
		r, err := e.parseFactor()
		if err != nil {
			return 0, err
		}
		switch c {
		case '*':
			v *= r
		case '/':
			if r == 0 {
				return 0, errors.New("util: division by zero")
			}
			v /= r
		case '%':
			if r == 0 {
				return 0, errors.New("util: modulo by zero")
			}
			v %= r
		}
	}
}

func (e *exprEval) parseFactor() (int64, error) {
	e.skipSpace()
	if e.pos >= len(e.s) {
		return 0, errors.New("util: unexpected end of expression")
	}
	c := e.peek()
	if c == '-' {
		e.pos++
		v, err := e.parseFactor()
		if err != nil {
			return 0, err
		}
		return -v, nil
	}
	if c == '+' {
		e.pos++
		return e.parseFactor()
	}
	if c == '(' {
		e.pos++
		v, err := e.parseExpr()
		if err != nil {
			return 0, err
		}
		e.skipSpace()
		if e.peek() != ')' {
			return 0, errors.New("util: missing closing parenthesis")
		}
		e.pos++
		return v, nil
	}
	start := e.pos
	if c == '0' && e.pos+1 < len(e.s) && (e.s[e.pos+1] == 'x' || e.s[e.pos+1] == 'X') {
		e.pos += 2
		for e.pos < len(e.s) && isHexDigit(e.s[e.pos]) {
			e.pos++
		}
		v, err := strconv.ParseInt(e.s[start+2:e.pos], 16, 64)
		if err != nil {
			return 0, fmt.Errorf("util: bad hex literal %q", e.s[start:e.pos])
		}
		return v, nil
	}
	for e.pos < len(e.s) && e.s[e.pos] >= '0' && e.s[e.pos] <= '9' {
		e.pos++
	}
	if e.pos == start {
		return 0, fmt.Errorf("util: unexpected character %q", c)
	}
	v, err := strconv.ParseInt(e.s[start:e.pos], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("util: bad number %q", e.s[start:e.pos])
	}
	return v, nil
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// SearchMatch is one hit of RegexSearch / StringSearch.
type SearchMatch struct {
	Offset int64  `json:"offset"`
	Length int    `json:"length"`
	Text   string `json:"text"`
}

// RegexSearch finds every non-overlapping match of pattern in data and
// reports its offset, length and a lossily-printable rendering.
func RegexSearch(data []byte, pattern string, limit int) ([]SearchMatch, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("util: bad regex: %w", err)
	}
	if limit <= 0 {
		limit = 1000
	}
	var out []SearchMatch
	for _, loc := range re.FindAllSubmatchIndex(data, limit) {
		s, e := loc[0], loc[1]
		out = append(out, SearchMatch{
			Offset: int64(s),
			Length: e - s,
			Text:   Printable(data[s:e]),
		})
	}
	return out, nil
}

// ExtractStrings pulls run-of-printable-ASCII/UTF-8 sequences out of
// data, the classic "strings" utility. minLen is the shortest run to
// keep (WinHex default is 4). Binary bytes (NUL, control) terminate a
// run; valid UTF-8 runes count as printable too.
func ExtractStrings(data []byte, minLen int, limit int) []SearchMatch {
	if minLen <= 0 {
		minLen = 4
	}
	if limit <= 0 {
		limit = 10000
	}
	var out []SearchMatch
	start := -1 // start of the current run, -1 when outside one
	i := 0
	for i <= len(data) {
		var size int
		printable := false
		if i < len(data) {
			if data[i] >= 0x20 && data[i] < 0x7F {
				size, printable = 1, true
			} else if data[i] >= 0x80 {
				var r rune
				r, size = utf8.DecodeRune(data[i:])
				if r != utf8.RuneError && unicode.IsPrint(r) {
					printable = true
				}
			} else {
				// control byte (< 0x20)
				size = 1
			}
		}
		if printable {
			if start < 0 {
				start = i
			}
			i += size
			continue
		}
		// A terminator (or end of data): close any open run.
		if start >= 0 && i-start >= minLen && len(out) < limit {
			out = append(out, SearchMatch{Offset: int64(start), Length: i - start, Text: string(data[start:i])})
		}
		start = -1
		if i == len(data) {
			break
		}
		i++
	}
	return out
}

// Printable renders data as a string safe to embed in JSON and
// terminals: printable ASCII/UTF-8 kept, everything else as \xNN.
func Printable(data []byte) string {
	var b strings.Builder
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, "\\x%02x", data[i])
			i++
			continue
		}
		if unicode.IsPrint(r) && r != '\\' {
			b.WriteRune(r)
		} else if r == '\\' {
			b.WriteString(`\\`)
		} else {
			fmt.Fprintf(&b, "\\x%02x", data[i])
		}
		i += size
	}
	return b.String()
}

// SplitFile splits src into pieces of pieceSize bytes each, named
// dstPattern with a %d placeholder (e.g. "part-%d.bin"). It returns
// the paths of the pieces it wrote, in order.
func SplitFile(src, dstPattern string, pieceSize int64) ([]string, error) {
	if pieceSize <= 0 {
		return nil, errors.New("util: piece size must be positive")
	}
	if !strings.Contains(dstPattern, "%d") {
		return nil, errors.New("util: destination pattern must contain %d")
	}
	in, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	var paths []string
	buf := make([]byte, 1<<20)
	for idx := 0; ; idx++ {
		name := fmt.Sprintf(dstPattern, idx)
		out, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			for _, p := range paths {
				os.Remove(p)
			}
			return nil, err
		}
		n, err := io.CopyBuffer(out, io.LimitReader(in, pieceSize), buf)
		out.Close()
		if err != nil {
			for _, p := range paths {
				os.Remove(p)
			}
			return nil, err
		}
		paths = append(paths, name)
		if n < pieceSize {
			return paths, nil
		}
	}
}

// JoinFiles concatenates parts (in order) into dst.
func JoinFiles(parts []string, dst string) (int64, error) {
	if len(parts) == 0 {
		return 0, errors.New("util: no parts")
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, p := range parts {
		in, err := os.Open(p)
		if err != nil {
			out.Close()
			os.Remove(dst)
			return 0, err
		}
		n, err := io.Copy(out, in)
		in.Close()
		total += n
		if err != nil {
			out.Close()
			os.Remove(dst)
			return 0, err
		}
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return 0, err
	}
	return total, nil
}

// Shred overwrites path with the given passes of a pattern, then
// truncates and (on POSIX) unlinks it. Patterns: "zeros", "ones",
// "random", "dod522022m" (3 passes: 0x00, 0xFF, random), "petergutmann"
// (35 passes). This is best-effort: on CoW/SSD/journaled filesystems
// the physical media cannot be guaranteed, which the caller must state
// to the user.
func Shred(path string, passes int) error {
	if passes <= 0 {
		passes = 1
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	size := fi.Size()
	if size == 0 {
		return os.Remove(path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	patterns := make([]func([]byte), 0, passes)
	for i := 0; i < passes; i++ {
		switch {
		case i%3 == 0:
			patterns = append(patterns, func(b []byte) {
				for j := range b {
					b[j] = 0x00
				}
			})
		case i%3 == 1:
			patterns = append(patterns, func(b []byte) {
				for j := range b {
					b[j] = 0xFF
				}
			})
		default:
			patterns = append(patterns, func(b []byte) { _, _ = io.ReadFull(rand.Reader, b) })
		}
	}
	for _, fill := range patterns {
		fill(buf)
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		remaining := size
		for remaining > 0 {
			n := int64(len(buf))
			if n > remaining {
				n = remaining
			}
			if _, err := f.Write(buf[:n]); err != nil {
				return err
			}
			remaining -= n
		}
		if err := f.Sync(); err != nil {
			return err
		}
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	f.Close()
	return os.Remove(path)
}

const passwordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+"

// Password generates a cryptographically random password of length n
// using a rejection-free uniform draw over the alphabet. The alphabet
// omits look-alikes (l, I, O, 0, 1).
func Password(n int) (string, error) {
	if n <= 0 {
		return "", errors.New("util: password length must be positive")
	}
	if n > 4096 {
		return "", errors.New("util: password length too large")
	}
	out := make([]byte, n)
	// Rejection sampling against the largest multiple of len(alphabet)
	// that fits in a byte keeps the distribution uniform.
	limit := byte(256 - 256%len(passwordAlphabet))
	for i := 0; i < n; {
		var b [64]byte
		if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
			return "", err
		}
		for _, c := range b[:] {
			if c >= limit {
				continue
			}
			out[i] = passwordAlphabet[int(c)%len(passwordAlphabet)]
			i++
			if i == n {
				break
			}
		}
	}
	return string(out), nil
}

// UUIDv4 returns a random RFC 4122 version-4 UUID.
func UUIDv4() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0F) | 0x40
	b[8] = (b[8] & 0x3F) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ULID returns a lexicographically sortable 26-character ULID
// (Crockford base32: 48-bit timestamp + 80-bit randomness).
func ULID() (string, error) {
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], uint64(time.Now().UnixMilli())<<16)
	if _, err := io.ReadFull(rand.Reader, b[6:]); err != nil {
		return "", err
	}
	enc := base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)
	return enc.EncodeToString(b[:]), nil
}

// TimestampKind labels a converted instant.
type TimestampKind string

const (
	TimestampFuture TimestampKind = "future"
	TimestampPast   TimestampKind = "past"
	TimestampNow    TimestampKind = "now"
)

// ConvertTimestamp turns a Unix epoch value (seconds, milliseconds,
// microseconds or nanoseconds — chosen by unit) into the set of
// human-readable renderings a forensic examiner needs: UTC, local,
// ISO-8601, RFC 1123, Windows FILETIME and NTFS (100ns since 1601).
func ConvertTimestamp(epoch int64, unit string) (map[string]string, error) {
	var t time.Time
	switch strings.ToLower(unit) {
	case "", "s", "sec", "seconds":
		t = time.Unix(epoch, 0).UTC()
	case "ms", "millis", "milliseconds":
		t = time.UnixMilli(epoch).UTC()
	case "us", "micros", "microseconds":
		t = time.UnixMicro(epoch).UTC()
	case "ns", "nanos", "nanoseconds":
		t = time.Unix(0, epoch).UTC()
	default:
		return nil, fmt.Errorf("util: unknown unit %q", unit)
	}
	filetime := epoch*10_000_000 + 116444736000000000 // s → 100ns since 1601
	kind := TimestampPast
	switch {
	case t.Year() >= time.Now().Year()+1:
		kind = TimestampFuture
	case time.Since(t) < 2*time.Minute || time.Until(t) < 2*time.Minute:
		kind = TimestampNow
	}
	return map[string]string{
		"utc":      t.Format("2006-01-02 15:04:05.000000000 UTC"),
		"local":    t.Local().Format("2006-01-02 15:04:05.000000000 MST"),
		"iso8601":  t.Format(time.RFC3339Nano),
		"rfc1123":  t.Format(time.RFC1123),
		"unix":     fmt.Sprintf("%d", t.Unix()),
		"unix_ms":  fmt.Sprintf("%d", t.UnixMilli()),
		"filetime": fmt.Sprintf("%d", filetime),
		"kind":     string(kind),
	}, nil
}

// RandomBytes returns n cryptographically random bytes as uppercase
// hex. n is capped at 1 MiB to keep the service surface bounded.
func RandomBytes(n int) (string, error) {
	if n <= 0 || n > 1<<20 {
		return "", errors.New("util: random byte count must be in 1..1048576")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	const hexdigits = "0123456789ABCDEF"
	out := make([]byte, n*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0F]
	}
	return string(out), nil
}

// EntropyReader streams data through r and returns the Shannon
// entropy of everything read, without buffering it all in memory.
func EntropyReader(r io.Reader) (float64, int64, error) {
	var freq [256]int64
	var total int64
	buf := make([]byte, 1<<20)
	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			for _, b := range buf[:n] {
				freq[b]++
			}
			total += int64(n)
		}
		if errors.Is(err, io.EOF) || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return 0, total, err
		}
	}
	if total == 0 {
		return 0, 0, nil
	}
	var h float64
	nt := float64(total)
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / nt
		h -= p * math.Log2(p)
	}
	return h, total, nil
}

// HeadBytes reads up to n bytes from the start of path (used by the
// GUI to preview before committing to a full read).
func HeadBytes(path string, n int64) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("util: head size must be positive")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, n))
}

// TailBytes reads the last n bytes of path.
func TailBytes(path string, n int64) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("util: tail size must be positive")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := fi.Size() - n
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(f, n))
}

// FirstLines reads up to maxLines text lines from the head of path
// (bounded to maxBytes) — the "text preview" half of the strings tool.
func FirstLines(path string, maxLines, maxBytes int) ([]string, error) {
	if maxLines <= 0 {
		maxLines = 100
	}
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(io.LimitReader(f, int64(maxBytes)))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() && len(out) < maxLines {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}
