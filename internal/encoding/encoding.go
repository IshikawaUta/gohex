// Package bincoding provides text/binary encodings used by the hex view,
// search engine and converters: ASCII, UTF-8, UTF-16 (LE/BE), EBCDIC CP037,
// plus byte/hex-string conversion helpers, Intel HEX and Motorola S-record
// encoders/decoders.
package bincoding

import (
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Encoding identifies a character encoding supported by the hex view and the
// text search path.
type Encoding int

const (
	// ASCII is 7-bit US-ASCII (bytes ≥ 0x80 render as U+FFFD).
	ASCII Encoding = iota
	// UTF8 is Unicode encoded as UTF-8.
	UTF8
	// UTF16LE is UTF-16 little-endian (no BOM assumed for raw ranges).
	UTF16LE
	// UTF16BE is UTF-16 big-endian.
	UTF16BE
	// EBCDIC is IBM code page 037.
	EBCDIC
)

// String returns the display name used in the status bar and preferences.
func (e Encoding) String() string {
	switch e {
	case ASCII:
		return "ASCII"
	case UTF8:
		return "UTF-8"
	case UTF16LE:
		return "UTF-16 LE"
	case UTF16BE:
		return "UTF-16 BE"
	case EBCDIC:
		return "EBCDIC"
	}
	return "unknown"
}

// ParseEncoding resolves a display name (case-insensitive) to an Encoding.
func ParseEncoding(s string) (Encoding, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ASCII":
		return ASCII, nil
	case "UTF-8", "UTF8":
		return UTF8, nil
	case "UTF-16 LE", "UTF16LE", "UTF-16LE":
		return UTF16LE, nil
	case "UTF-16 BE", "UTF16BE", "UTF-16BE":
		return UTF16BE, nil
	case "EBCDIC":
		return EBCDIC, nil
	}
	return ASCII, fmt.Errorf("bincoding: unknown encoding %q", s)
}

// All lists every supported encoding, for preferences UIs.
func All() []Encoding { return []Encoding{ASCII, UTF8, UTF16LE, UTF16BE, EBCDIC} }

// Decode converts raw bytes to a string in the given encoding. Invalid
// sequences are replaced with U+FFFD rather than producing an error, because
// the primary consumer is the on-screen text column of arbitrary binary data.
func Decode(enc Encoding, b []byte) string {
	switch enc {
	case UTF8:
		if utf8.Valid(b) {
			return string(b)
		}
		return strings.ToValidUTF8(string(b), string(utf8.RuneError))
	case UTF16LE:
		return string(utf16.Decode(decodeUTF16(b, false)))
	case UTF16BE:
		return string(utf16.Decode(decodeUTF16(b, true)))
	case EBCDIC:
		var sb strings.Builder
		sb.Grow(len(b))
		for _, c := range b {
			sb.WriteRune(rune(ebcdicToUnicode[c]))
		}
		return sb.String()
	default: // ASCII
		var sb strings.Builder
		sb.Grow(len(b))
		for _, c := range b {
			if c < 0x80 {
				sb.WriteByte(c)
			} else {
				sb.WriteRune(utf8.RuneError)
			}
		}
		return sb.String()
	}
}

func decodeUTF16(b []byte, big bool) []uint16 {
	n := len(b) / 2
	out := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		if big {
			out = append(out, uint16(b[2*i])<<8|uint16(b[2*i+1]))
		} else {
			out = append(out, uint16(b[2*i+1])<<8|uint16(b[2*i]))
		}
	}
	return out
}

// Encode converts s to raw bytes in the given encoding. Characters that the
// target encoding cannot represent become '?' (a common convention that keeps
// offsets predictable when round-tripping).
func Encode(enc Encoding, s string) []byte {
	switch enc {
	case UTF8:
		return []byte(s)
	case UTF16LE, UTF16BE:
		units := utf16.Encode([]rune(s))
		out := make([]byte, 0, len(units)*2)
		for _, u := range units {
			if enc == UTF16LE {
				out = append(out, byte(u), byte(u>>8))
			} else {
				out = append(out, byte(u>>8), byte(u))
			}
		}
		return out
	case EBCDIC:
		out := make([]byte, 0, len(s))
		for _, r := range s {
			if r > 0xFFFF {
				out = append(out, 0x6F) // '?' — outside the CP037 BMP table
				continue
			}
			out = append(out, unicodeToEBCDIC[r])
		}
		return out
	default: // ASCII
		out := make([]byte, 0, len(s))
		for _, r := range s {
			if r < 0x80 {
				out = append(out, byte(r))
			} else {
				out = append(out, '?')
			}
		}
		return out
	}
}

// ColumnText renders one text-column cell for a slice of raw bytes: printable
// characters pass through, everything else becomes '.' — the classic hex
// editor presentation. Multi-byte and non-ASCII encodings (UTF-8, UTF-16,
// EBCDIC) are decoded first so real characters display correctly.
func ColumnText(enc Encoding, b []byte) string {
	if enc == ASCII {
		var sb strings.Builder
		sb.Grow(len(b))
		for _, c := range b {
			if c >= 0x20 && c < 0x7F {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		return sb.String()
	}
	s := Decode(enc, b)
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			sb.WriteByte('.')
		case r < 0x20 || r == 0x7F || (r >= 0x80 && r < 0xA0):
			sb.WriteByte('.')
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
