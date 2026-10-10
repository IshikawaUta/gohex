// Package compare implements byte-range comparison of two read-only
// sources: given two documents or images, it reports which contiguous
// byte ranges differ, how many bytes agree and where the first difference
// sits. It is the engine behind the binary-compare utility (WinHex file
// compare); everything here is strictly read-only.
package compare

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

const (
	// BlockSize is the granularity of the equal-run fast path. Identical
	// regions are skipped with a single bytes.Equal per block; only blocks
	// that differ are scanned byte by byte.
	BlockSize = 64 << 10

	// DefaultMaxRanges caps how many differing ranges a result carries;
	// beyond the cap the result is marked Truncated but the byte counts
	// stay exact.
	DefaultMaxRanges = 500
)

// Range is one contiguous run of differing bytes at Start of Length bytes.
type Range struct {
	Start  int64 `json:"start"`
	Length int64 `json:"length"`
}

// Result summarizes a comparison. FirstDiff is -1 when the common prefix
// is byte-identical; Identical additionally requires equal sizes.
type Result struct {
	SizeA     int64   `json:"sizeA"`
	SizeB     int64   `json:"sizeB"`
	Equal     int64   `json:"equal"`
	Differing int64   `json:"differing"`
	FirstDiff int64   `json:"firstDiff"`
	Ranges    []Range `json:"ranges"`
	Truncated bool    `json:"truncated"`
	Identical bool    `json:"identical"`
}

// Compare reads sizeA bytes from a and sizeB bytes from b and reports the
// differing byte ranges (up to maxRanges; 0 selects DefaultMaxRanges).
// The shorter input contributes no reads past its end: bytes that exist
// only in the longer input form one trailing differing range.
func Compare(a, b io.ReaderAt, sizeA, sizeB int64, maxRanges int) (*Result, error) {
	if a == nil || b == nil {
		return nil, errors.New("compare: nil source")
	}
	if sizeA < 0 || sizeB < 0 {
		return nil, errors.New("compare: negative size")
	}
	if maxRanges <= 0 {
		maxRanges = DefaultMaxRanges
	}
	res := &Result{
		SizeA:     sizeA,
		SizeB:     sizeB,
		FirstDiff: -1,
	}

	common := min(sizeA, sizeB)
	bufA := make([]byte, BlockSize)
	bufB := make([]byte, BlockSize)

	var offset int64
	var open *Range // range currently being extended, nil when outside
	closeRange := func(end int64) {
		if open == nil {
			return
		}
		open.Length = end - open.Start
		if len(res.Ranges) < maxRanges {
			res.Ranges = append(res.Ranges, *open)
		} else {
			res.Truncated = true
		}
		open = nil
	}
	noteDiff := func(pos int64) {
		if res.FirstDiff < 0 {
			res.FirstDiff = pos
		}
		res.Differing++
		if open == nil {
			if len(res.Ranges) < maxRanges {
				open = &Range{Start: pos}
			} else {
				res.Truncated = true
			}
		}
	}

	for offset < common {
		n := min(int64(BlockSize), common-offset)
		if nr, err := a.ReadAt(bufA[:n], offset); err != nil && (!errors.Is(err, io.EOF) || int64(nr) != n) {
			return nil, fmt.Errorf("compare: read A at 0x%x: %w", offset, err)
		}
		if nr, err := b.ReadAt(bufB[:n], offset); err != nil && (!errors.Is(err, io.EOF) || int64(nr) != n) {
			return nil, fmt.Errorf("compare: read B at 0x%x: %w", offset, err)
		}
		if bytes.Equal(bufA[:n], bufB[:n]) {
			res.Equal += n
			offset += n
			continue
		}
		for i := int64(0); i < n; i++ {
			if bufA[i] != bufB[i] {
				noteDiff(offset + i)
			} else {
				closeRange(offset + i)
				res.Equal++
			}
		}
		offset += n
	}
	closeRange(common)

	// Bytes past the shorter input differ by definition.
	if sizeA != sizeB {
		if res.FirstDiff < 0 {
			res.FirstDiff = common
		}
		res.Differing += abs(sizeA - sizeB)
		tail := Range{Start: common, Length: abs(sizeA - sizeB)}
		if len(res.Ranges) < maxRanges {
			res.Ranges = append(res.Ranges, tail)
		} else {
			res.Truncated = true
		}
	}
	res.Identical = res.Differing == 0
	return res, nil
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
