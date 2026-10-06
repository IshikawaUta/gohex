package bincoding

import (
	"fmt"
	"strings"
)

// HexToBytes parses a hex string into bytes. It tolerates spaces, commas,
// colons, dashes and a leading "0x" so users can paste from any source:
//
//	4D 5A 90 00  →  []byte{0x4D,0x5A,0x90,0x00}
//	0x4d5a9000   →  same
//
// An odd number of hex digits is an error (no implicit leading zero), which
// prevents silent misalignment of forensic signatures.
func HexToBytes(s string) ([]byte, error) {
	var cleaned strings.Builder
	cleaned.Grow(len(s))
	flushed := false
	for _, r := range s {
		switch {
		case r == ' ' || r == ',' || r == ':' || r == '-' || r == '\t' || r == '\n' || r == '\r':
			if flushed {
				cleaned.WriteByte(' ')
				flushed = false
			}
		default:
			cleaned.WriteRune(r)
			flushed = true
		}
	}
	t := strings.TrimSpace(cleaned.String())
	if t == "" {
		return nil, nil
	}
	t = strings.TrimPrefix(strings.TrimPrefix(t, "0x"), "0X")
	// Tokenise on whitespace: each token must contain an even number of hex
	// digits; tokens are concatenated byte-wise.
	var out []byte
	for _, tok := range strings.Fields(t) {
		if len(tok)%2 != 0 {
			return nil, fmt.Errorf("bincoding: odd number of hex digits in %q", tok)
		}
		for i := 0; i < len(tok); i += 2 {
			hi, err := hexVal(tok[i])
			if err != nil {
				return nil, err
			}
			lo, err := hexVal(tok[i+1])
			if err != nil {
				return nil, err
			}
			out = append(out, hi<<4|lo)
		}
	}
	return out, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("bincoding: invalid hex digit %q", c)
}

// BytesToHex renders bytes as uppercase hex with the given separator
// ("" for a compact string, " " for the classic spaced form).
func BytesToHex(b []byte, sep string) string {
	var sb strings.Builder
	sb.Grow(len(b)*(2+len(sep)) - len(sep))
	for i, c := range b {
		if i > 0 && sep != "" {
			sb.WriteString(sep)
		}
		sb.WriteString(upperHexByte(c))
	}
	return sb.String()
}

const hexDigits = "0123456789ABCDEF"

func upperHexByte(c byte) string {
	return string([]byte{hexDigits[c>>4], hexDigits[c&0x0F]})
}

// SpacedHex renders bytes in the classic WinHex style: "4D 5A 90 00".
func SpacedHex(b []byte) string { return BytesToHex(b, " ") }
