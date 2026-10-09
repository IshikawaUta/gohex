package memory

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

// Snappy framed-format decoder, used by AVML captures. The framing is
// Google's stream format: a stream-identifier frame followed by chunks of
// type 0x00 (compressed) or 0x01 (uncompressed data), each carrying a
// CRC-32C of its uncompressed bytes; chunk types >= 0x80 are skippable.
// Implemented in-house so the memory package stays dependency-free.

const (
	snappyStreamIDLen   = 10
	snappyChunkHdr      = 4 // 1-byte type + 3-byte little-endian length
	snappyChunkComp     = 0x00
	snappyChunkUncomp   = 0x01
	snappyChunkSkippMin = 0x80
	maxSnappyBlock      = 64 << 10 // the snappy block format caps at 64 KiB
)

var (
	snappyStreamID     = []byte{0xFF, 0x06, 0x00, 0x00, 's', 'N', 'a', 'P', 'p', 'Y'}
	crc32cTable        = crc32.MakeTable(crc32.Castagnoli)
	errSnappyMalformed = errors.New("memory: malformed snappy stream")
)

// decodeSnappyFrames decompresses one Snappy framed stream and stops as
// soon as expect uncompressed bytes have been produced, so a trailing
// AVML length trailer is never consumed. Chunk headers carry a three-byte
// little-endian length; CRC-32C of every data chunk is verified (masked as
// the framing spec requires). Repeated stream-identifier chunks are
// ignored, per the framing spec.
func decodeSnappyFrames(src []byte, expect int64) ([]byte, error) {
	if len(src) < snappyStreamIDLen || !bytesEqualPrefix(src, snappyStreamID) {
		return nil, errors.New("memory: missing snappy stream identifier")
	}
	pos := snappyStreamIDLen
	out := make([]byte, 0, expect)
	for int64(len(out)) < expect {
		if pos+snappyChunkHdr > len(src) {
			return nil, errors.New("memory: truncated snappy frame header")
		}
		ctype := src[pos]
		clen := int(src[pos+1]) | int(src[pos+2])<<8 | int(src[pos+3])<<16
		pos += snappyChunkHdr
		if pos+clen > len(src) {
			return nil, errors.New("memory: truncated snappy frame")
		}
		payload := src[pos : pos+clen]
		pos += clen
		var chunk []byte
		switch {
		case ctype == snappyChunkComp:
			if clen < 4 {
				return nil, errors.New("memory: truncated snappy compressed frame")
			}
			raw, err := decodeSnappyBlock(payload[4:])
			if err != nil {
				return nil, err
			}
			chunk = raw
		case ctype == snappyChunkUncomp:
			if clen < 4 {
				return nil, errors.New("memory: truncated snappy uncompressed frame")
			}
			chunk = payload[4:]
		case ctype == 0xFF: // repeated stream identifier: must be well-formed
			if clen != 6 || string(payload) != "sNaPpY" {
				return nil, errors.New("memory: bad repeated snappy stream identifier")
			}
			continue
		case ctype >= snappyChunkSkippMin:
			continue // padding / reserved skippable
		default:
			return nil, fmt.Errorf("memory: unsupported snappy chunk type %#x", ctype)
		}
		if int64(len(out))+int64(len(chunk)) > expect {
			return nil, errors.New("memory: snappy output exceeds expected length")
		}
		if maskedCRC32C(chunk) != binary.LittleEndian.Uint32(payload[:4]) {
			return nil, errors.New("memory: snappy frame CRC mismatch")
		}
		out = append(out, chunk...)
	}
	return out, nil
}

// decodeSnappyBlock decompresses one raw snappy block: a varint
// uncompressed length followed by literal and copy tags. Tag types are
// the low two bits: 00 literal, 01 copy with 1-byte offset, 10 copy with
// 2-byte offset, 11 copy with 4-byte offset.
func decodeSnappyBlock(src []byte) ([]byte, error) {
	uLen, n := binary.Uvarint(src)
	if n <= 0 || uLen > maxSnappyBlock {
		return nil, errSnappyMalformed
	}
	dst := make([]byte, int(uLen))
	di := 0
	si := n
	for si < len(src) {
		tag := src[si]
		si++
		switch tag & 3 {
		case 0: // literal
			ln := int(tag >> 2)
			if ln < 60 {
				ln++
			} else {
				nb := ln - 59 // 1..4 length bytes follow, holding len-1
				if si+nb > len(src) {
					return nil, errSnappyMalformed
				}
				ln = 0
				for i := 0; i < nb; i++ {
					ln |= int(src[si+i]) << (8 * i)
				}
				si += nb
				ln++
			}
			if ln <= 0 || si+ln > len(src) || di+ln > len(dst) {
				return nil, errSnappyMalformed
			}
			di += copy(dst[di:], src[si:si+ln])
			si += ln
		case 1: // copy with 1-byte offset: len 4..11, offset 11 bits
			length := 4 + int(tag>>2)&7
			if si+1 > len(src) {
				return nil, errSnappyMalformed
			}
			offset := int(tag>>5)<<8 | int(src[si])
			si++
			if err := copyBackref(dst, &di, length, offset); err != nil {
				return nil, err
			}
		case 2: // copy with 2-byte offset: len 1..64, offset u16
			length := 1 + int(tag>>2)
			if si+2 > len(src) {
				return nil, errSnappyMalformed
			}
			offset := int(binary.LittleEndian.Uint16(src[si:]))
			si += 2
			if err := copyBackref(dst, &di, length, offset); err != nil {
				return nil, err
			}
		default: // copy with 4-byte offset: len 1..64, offset u32
			length := 1 + int(tag>>2)
			if si+4 > len(src) {
				return nil, errSnappyMalformed
			}
			offset := int(binary.LittleEndian.Uint32(src[si:]))
			si += 4
			if err := copyBackref(dst, &di, length, offset); err != nil {
				return nil, err
			}
		}
	}
	if di != len(dst) {
		return nil, errSnappyMalformed
	}
	return dst, nil
}

// copyBackref copies length bytes from di-offset into dst[di:], expanding
// byte-wise because copies may overlap (RLE-style backreferences).
func copyBackref(dst []byte, di *int, length, offset int) error {
	if offset <= 0 || offset > *di || *di+length > len(dst) {
		return errSnappyMalformed
	}
	for i := 0; i < length; i++ {
		dst[*di+i] = dst[*di-offset+i]
	}
	*di += length
	return nil
}

func bytesEqualPrefix(b, prefix []byte) bool {
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

// maskedCRC32C is the Snappy framing CRC: CRC-32C rotated and biased, as
// specified by the stream format.
func maskedCRC32C(data []byte) uint32 {
	c := crc32.Checksum(data, crc32cTable)
	return ((c >> 15) | (c << 17)) + 0xa282ead8
}
