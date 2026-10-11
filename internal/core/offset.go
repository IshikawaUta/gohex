package core

import (
	"fmt"
	"strconv"
	"strings"
)

// OffsetBase selects the default numeral base for ParseOffset when the input
// carries no explicit prefix. Hex is the default because offsets in a hex
// editor are conventionally hexadecimal.
type OffsetBase int

const (
	// BaseHex treats unprefixed input as hexadecimal (default).
	BaseHex OffsetBase = iota
	// BaseDec treats unprefixed input as decimal.
	BaseDec
)

// ParseOffset parses a user-supplied offset expression.
//
// Accepted forms:
//
//	0x1A / 0X1a     explicit hex
//	1A / 1a         hex (default) or decimal depending on base
//	+10 / -10       relative to a reference point (ref)
//	$1A             hex, WinHex-style
//	1KB / 1MB / 1GB size suffixes (decimal multiples of 1024)
//	128s / 512S     sectors of size sectorSize (e.g. "100s" = offset of
//	                 sector 100; requires sectorSize > 0)
//
// The returned value for relative expressions is ref+delta; callers pass the
// cursor offset. The result is never negative: ErrNegativeOffset is returned
// when it would be.
func ParseOffset(s string, base OffsetBase, ref int64, sectorSize int64) (int64, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, fmt.Errorf("core: empty offset")
	}
	rel := false // relative iff an explicit sign was present
	neg := false
	switch t[0] {
	case '+':
		rel = true
		t = t[1:]
	case '-':
		rel = true
		neg = true
		t = t[1:]
	}
	if t == "" {
		return 0, fmt.Errorf("core: invalid offset %q", s)
	}

	// Sector suffix: 100s
	if len(t) > 1 && (t[len(t)-1] == 's' || t[len(t)-1] == 'S') {
		if sectorSize <= 0 {
			return 0, fmt.Errorf("core: sector offset %q requires a sector size", s)
		}
		n, err := strconv.ParseInt(t[:len(t)-1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("core: invalid sector offset %q: %w", s, err)
		}
		return applySign(rel, neg, ref, n*sectorSize, s)
	}
	// Size suffix: KB/MB/GB/TB
	if n, ok, err := parseSizeSuffix(t); err != nil {
		return 0, err
	} else if ok {
		return applySign(rel, neg, ref, n, s)
	}

	if t[0] == '$' {
		n, err := strconv.ParseInt(t[1:], 16, 64)
		if err != nil {
			return 0, fmt.Errorf("core: invalid hex offset %q: %w", s, err)
		}
		return applySign(rel, neg, ref, n, s)
	}
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		n, err := strconv.ParseInt(t[2:], 16, 64)
		if err != nil {
			return 0, fmt.Errorf("core: invalid hex offset %q: %w", s, err)
		}
		return applySign(rel, neg, ref, n, s)
	}
	if !rel && base == BaseDec {
		n, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("core: invalid decimal offset %q: %w", s, err)
		}
		return n, nil
	}
	n, err := strconv.ParseInt(t, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("core: invalid offset %q: %w", s, err)
	}
	return applySign(rel, neg, ref, n, s)
}

func applySign(rel, neg bool, ref, n int64, orig string) (int64, error) {
	out := n
	if rel {
		if neg {
			out = ref - n
		} else {
			out = ref + n
		}
	}
	if out < 0 {
		return 0, fmt.Errorf("core: offset %q resolves negative: %w", orig, ErrNegativeOffset)
	}
	return out, nil
}

func parseSizeSuffix(t string) (int64, bool, error) {
	var mult int64
	upper := strings.ToUpper(t)
	switch {
	case strings.HasSuffix(upper, "KB"):
		mult = 1 << 10
	case strings.HasSuffix(upper, "MB"):
		mult = 1 << 20
	case strings.HasSuffix(upper, "GB"):
		mult = 1 << 30
	case strings.HasSuffix(upper, "TB"):
		mult = 1 << 40
	default:
		return 0, false, nil
	}
	num := t[:len(t)-2]
	n, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, false, fmt.Errorf("core: invalid size offset %q: %w", t, err)
	}
	if n < 0 {
		return 0, false, fmt.Errorf("core: negative size offset %q: %w", t, ErrNegativeOffset)
	}
	return int64(n * float64(mult)), true, nil
}

// FormatOffset renders off in the requested radix with fixed width padding
// (minimum width hex digits, uppercase) as used by the offset column.
func FormatOffset(off int64, radix OffsetBase, width int) string {
	if width <= 0 {
		width = 8
	}
	if radix == BaseDec {
		return fmt.Sprintf("%*d", width, off)
	}
	return fmt.Sprintf("%0*X", width, off)
}
