package compare

import (
	"bytes"
	"testing"
)

func TestCompareIdentical(t *testing.T) {
	data := []byte("same bytes on both sides")
	res, err := Compare(bytes.NewReader(data), bytes.NewReader(data),
		int64(len(data)), int64(len(data)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Identical || res.FirstDiff != -1 || len(res.Ranges) != 0 {
		t.Fatalf("res = %+v", res)
	}
	if res.Equal != int64(len(data)) || res.Differing != 0 {
		t.Fatalf("equal/differing = %d/%d", res.Equal, res.Differing)
	}
}

func TestCompareRanges(t *testing.T) {
	a := []byte("aaaaXXaaaaYYaaaa")
	b := []byte("aaaaBBaaaaZZaaaa")
	res, err := Compare(bytes.NewReader(a), bytes.NewReader(b),
		int64(len(a)), int64(len(b)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Identical || res.FirstDiff != 4 {
		t.Fatalf("res = %+v", res)
	}
	if len(res.Ranges) != 2 ||
		res.Ranges[0] != (Range{Start: 4, Length: 2}) ||
		res.Ranges[1] != (Range{Start: 10, Length: 2}) {
		t.Fatalf("ranges = %+v", res.Ranges)
	}
	if res.Equal != 12 || res.Differing != 4 {
		t.Fatalf("equal/differing = %d/%d", res.Equal, res.Differing)
	}
	if res.Truncated {
		t.Fatal("unexpected truncation")
	}
}

func TestCompareSizeMismatch(t *testing.T) {
	a := []byte("hello world")
	b := []byte("hello")
	res, err := Compare(bytes.NewReader(a), bytes.NewReader(b),
		int64(len(a)), int64(len(b)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.FirstDiff != 5 || res.Equal != 5 || res.Differing != 6 {
		t.Fatalf("res = %+v", res)
	}
	if len(res.Ranges) != 1 || res.Ranges[0] != (Range{Start: 5, Length: 6}) {
		t.Fatalf("ranges = %+v", res.Ranges)
	}
	if res.Identical {
		t.Fatal("should not be identical")
	}

	// Empty vs non-empty.
	res, err = Compare(bytes.NewReader(nil), bytes.NewReader(a), 0, int64(len(a)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.FirstDiff != 0 || res.Differing != int64(len(a)) ||
		len(res.Ranges) != 1 || res.Ranges[0].Start != 0 {
		t.Fatalf("res = %+v", res)
	}
}

func TestCompareBlockBoundary(t *testing.T) {
	// Difference exactly at the BlockSize boundary and across it.
	a := make([]byte, BlockSize*2+10)
	b := make([]byte, BlockSize*2+10)
	copy(a, bytes.Repeat([]byte{0x55}, len(a)))
	copy(b, a)
	b[BlockSize-1] = 0xAA
	b[BlockSize+5] = 0xBB
	res, err := Compare(bytes.NewReader(a), bytes.NewReader(b),
		int64(len(a)), int64(len(b)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.FirstDiff != BlockSize-1 || len(res.Ranges) != 2 {
		t.Fatalf("res = %+v", res)
	}
	if res.Ranges[0] != (Range{Start: BlockSize - 1, Length: 1}) ||
		res.Ranges[1] != (Range{Start: BlockSize + 5, Length: 1}) {
		t.Fatalf("ranges = %+v", res.Ranges)
	}
}

func TestCompareTruncation(t *testing.T) {
	// 10 isolated single-byte differences, cap at 3 ranges.
	a := bytes.Repeat([]byte{0x11}, 100)
	b := bytes.Clone(a)
	for i := 5; i < 100; i += 10 {
		b[i] ^= 0xFF
	}
	res, err := Compare(bytes.NewReader(a), bytes.NewReader(b), 100, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Ranges) != 3 || !res.Truncated {
		t.Fatalf("res = %+v", res)
	}
	if res.Differing != 10 {
		t.Fatalf("differing = %d, counts must stay exact", res.Differing)
	}
}

func TestCompareErrors(t *testing.T) {
	if _, err := Compare(nil, bytes.NewReader(nil), 0, 0, 0); err == nil {
		t.Fatal("nil source should fail")
	}
	if _, err := Compare(bytes.NewReader(nil), bytes.NewReader(nil), -1, 0, 0); err == nil {
		t.Fatal("negative size should fail")
	}
	// A source shorter than claimed forces a short read.
	short := bytes.NewReader([]byte("abc"))
	if _, err := Compare(short, bytes.NewReader([]byte("abcd")), 100, 4, 0); err == nil {
		t.Fatal("short source should fail")
	}
}
