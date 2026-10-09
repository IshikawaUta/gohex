package memory

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// --- test encoder helpers (shared with memory_test.go) ---------------------

// snappyBlockLiteral encodes data as one literal run (no compression), so
// tests can build snappy blocks without a real compressor.
func snappyBlockLiteral(data []byte) []byte {
	out := binary.AppendUvarint(nil, uint64(len(data)))
	n := len(data)
	if n <= 60 {
		out = append(out, byte(n-1)<<2)
	} else {
		nb := 1
		for v := n - 1; v > 0xFF; v >>= 8 {
			nb++
		}
		out = append(out, byte(59+nb)<<2)
		for i := 0; i < nb; i++ {
			out = append(out, byte((n-1)>>(8*i)))
		}
	}
	return append(out, data...)
}

// snappyFrame builds one framed chunk of the given type wrapping payload,
// stamped with the masked CRC-32C of plain. Chunk headers carry a
// three-byte little-endian length (the CRC bytes count toward it).
func snappyFrame(ctype byte, payload, plain []byte) []byte {
	ln := len(payload) + 4
	f := []byte{ctype, byte(ln), byte(ln >> 8), byte(ln >> 16)}
	f = binary.LittleEndian.AppendUint32(f, maskedCRC32C(plain))
	return append(f, payload...)
}

// snappyCompressedFrame frames data as a compressed chunk (literal-only
// block).
func snappyCompressedFrame(plain []byte) []byte {
	return snappyFrame(snappyChunkComp, snappyBlockLiteral(plain), plain)
}

// snappyUncompressedFrame frames data as an uncompressed chunk.
func snappyUncompressedFrame(plain []byte) []byte {
	return snappyFrame(snappyChunkUncomp, plain, plain)
}

func TestSnappyDecodeLiteralBlock(t *testing.T) {
	for _, n := range []int{1, 59, 60, 61, 300, 4096} {
		data := payloadFor(0x1000, n)
		got, err := decodeSnappyBlock(snappyBlockLiteral(data))
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("n=%d: decoded %d bytes, mismatch", n, len(got))
		}
	}
}

func TestSnappyDecodeCopyTags(t *testing.T) {
	// "xab" + copy1(offset=2, len=4) => "xababab" (the format doc's example).
	block := binary.AppendUvarint(nil, 7)
	block = append(block, 2<<2, 'x', 'a', 'b')
	block = append(block, 1, 2) // copy1: len 4, offset 2
	got, err := decodeSnappyBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "xababab" {
		t.Fatalf("got %q, want xababab", got)
	}

	// Copy1 with an 11-bit offset: literal 300 bytes, copy len 4 at
	// offset 300 (high 3 bits live in tag bits [5..7]).
	lit := payloadFor(0, 300)
	want := append(append([]byte(nil), lit...), lit[:4]...)
	block = binary.AppendUvarint(nil, uint64(len(want)))
	block = append(block, 61<<2, 0x2B, 0x01) // literal of 300 bytes (2-byte length)
	block = append(block, lit...)
	block = append(block, byte(1|(300>>8)<<5), byte(300&0xFF))
	got, err = decodeSnappyBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("copy1 11-bit offset: got %d bytes, want %d", len(got), len(want))
	}

	// Copy2 (2-byte offset): "abc" + copy(len 6, offset 3) = "abcabcabc".
	block = binary.AppendUvarint(nil, 9)
	block = append(block, 2<<2, 'a', 'b', 'c')
	block = append(block, (6-1)<<2|2, 3, 0) // copy2: len 6, offset 3
	got, err = decodeSnappyBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcabcabc" {
		t.Fatalf("copy2: got %q", got)
	}

	// Copy4 (4-byte offset): same shape with a 4-byte offset.
	block = binary.AppendUvarint(nil, 8)
	block = append(block, 2<<2, 'a', 'b', 'c')
	block = append(block, (5-1)<<2|3, 3, 0, 0, 0) // copy4: len 5, offset 3
	got, err = decodeSnappyBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcabcabc"[:8] {
		t.Fatalf("copy4: got %q", got)
	}
}

func TestSnappyBlockErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block []byte
	}{
		{"bad-varint", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}},
		{"huge-length", binary.AppendUvarint(nil, 1<<40)},
		{"truncated-literal", []byte{10, 60 << 2, 5}},
		{"literal-past-output", []byte{2, 5 << 2, 'a', 'b', 'c', 'd', 'e', 'f'}},
		{"copy-before-output", []byte{10, 1, 1}}, // copy with nothing to reference
		{"zero-offset", append([]byte{10, 4 << 2, 'a', 'b', 'c', 'd'}, 1, 0)},
		{"copy-past-output", append([]byte{5, 4 << 2, 'a', 'b', 'c', 'd'}, (4-1)<<2|2, 4, 0)},
		{"short-copy1", append([]byte{8, 4 << 2, 'a', 'b', 'c', 'd'}, 1)},
		{"short-copy2", append([]byte{8, 4 << 2, 'a', 'b', 'c', 'd'}, (4-1)<<2|2, 1)},
		{"short-copy4", append([]byte{8, 4 << 2, 'a', 'b', 'c', 'd'}, (4-1)<<2|3, 1, 0, 0)},
		{"output-underrun", []byte{10, 4 << 2, 'a', 'b', 'c', 'd'}}, // declares 10, writes 4
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeSnappyBlock(tc.block); err == nil {
				t.Fatal("err = nil, want error")
			}
		})
	}
}

func TestSnappyFramesDecode(t *testing.T) {
	plain := payloadFor(0x4000, 200)
	stream := append([]byte(nil), snappyStreamID...)
	stream = append(stream, snappyCompressedFrame(plain[:100])...)
	stream = append(stream, snappyUncompressedFrame(plain[100:])...)
	got, err := decodeSnappyFrames(stream, int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("decoded stream mismatch")
	}

	// Skippable chunks are ignored.
	stream = append([]byte(nil), snappyStreamID...)
	stream = append(stream, 0x80, 1, 0, 0, 0xAA) // skippable, 1 byte
	stream = append(stream, snappyCompressedFrame(plain)...)
	if got, err = decodeSnappyFrames(stream, int64(len(plain))); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("skippable: %v", err)
	}
}

func TestSnappyFrameErrors(t *testing.T) {
	plain := payloadFor(0, 16)
	good := append(append([]byte(nil), snappyStreamID...), snappyCompressedFrame(plain)...)

	badCRC := append([]byte(nil), good...)
	badCRC[snappyStreamIDLen+4] ^= 0xFF // flip a CRC bit

	// A repeated well-formed stream identifier is legal (concatenation).
	twoStreams := append(append([]byte(nil), good...), snappyStreamID...)
	twoStreams = append(twoStreams, snappyCompressedFrame(plain)...)

	for _, tc := range []struct {
		name    string
		data    []byte
		expect  int64
		wantErr string
	}{
		{"missing-id", snappyCompressedFrame(plain), 16, "stream identifier"},
		{"bad-id", append([]byte("bad-stream!!"), snappyCompressedFrame(plain)...), 16, "stream identifier"},
		{"truncated-header", good[:snappyStreamIDLen+2], 16, "truncated snappy frame header"},
		{"truncated-frame", good[:len(good)-5], 16, "truncated snappy frame"},
		{"bad-crc", badCRC, 16, "CRC mismatch"},
		{"output-exceeds", good, 10, "exceeds expected length"},
		{"bad-repeated-id", append(append([]byte(nil), snappyStreamID...), 0xFF, 2, 0, 0, 'X', 'Y'), 16, "bad repeated snappy stream identifier"},
		{"bad-chunk-type", append(append([]byte(nil), snappyStreamID...), 0x02, 5, 0, 0, 0, 0, 0, 0, 0), 16, "unsupported snappy chunk type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeSnappyFrames(tc.data, tc.expect)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}

	// A repeated well-formed stream identifier is ignored and decoding
	// continues into the next frame.
	got, err := decodeSnappyFrames(twoStreams, 32)
	if err != nil {
		t.Fatalf("repeated id: %v", err)
	}
	if !bytes.Equal(got, append(append([]byte(nil), plain...), plain...)) {
		t.Fatal("repeated id: decoded mismatch")
	}

	// A zero-length skippable chunk is legal and ignored.
	emptySkippable := append([]byte(nil), snappyStreamID...)
	emptySkippable = append(emptySkippable, 0x82, 0, 0, 0) // 0-byte skippable
	emptySkippable = append(emptySkippable, snappyCompressedFrame(plain)...)
	if _, err := decodeSnappyFrames(emptySkippable, 16); err != nil {
		t.Fatalf("zero-byte skippable: %v", err)
	}
}
