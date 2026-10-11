// Package hash provides the checksum/hash algorithms surfaced by the GoHex
// checksum panel and used for chain-of-custody verification: CRC-16/CRC-32,
// Adler-32, MD5, SHA-1, SHA-256, SHA-512, BLAKE2b, BLAKE3 and xxHash64.
//
// Cryptographic digests (SHA-256, SHA-512, BLAKE2b, BLAKE3) are recommended
// for evidence integrity; MD5 and SHA-1 are provided for interoperability
// with legacy evidence formats (see docs/security.md).
package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"io"

	"github.com/cespare/xxhash/v2"
	"golang.org/x/crypto/blake2b"
	"lukechampine.com/blake3"
)

// Algo identifies a supported algorithm.
type Algo string

// Supported algorithms.
const (
	CRC16      Algo = "CRC16-CCITT"
	CRC16IBM   Algo = "CRC16-IBM"
	CRC32      Algo = "CRC32"
	CRC32C     Algo = "CRC32-C"
	CRC64      Algo = "CRC64-XZ"
	Adler32    Algo = "Adler32"
	MD5        Algo = "MD5"
	SHA1       Algo = "SHA-1"
	SHA256     Algo = "SHA-256"
	SHA512     Algo = "SHA-512"
	BLAKE2b256 Algo = "BLAKE2b-256"
	BLAKE3     Algo = "BLAKE3"
	XXH64      Algo = "xxHash64"
)

// All lists every algorithm in the order shown by the checksum panel.
func All() []Algo {
	return []Algo{
		CRC16, CRC16IBM, CRC32, CRC32C, CRC64, Adler32,
		MD5, SHA1, SHA256, SHA512, BLAKE2b256, BLAKE3, XXH64,
	}
}

// Cryptographic reports whether the algorithm is collision-resistant and
// suitable for evidence integrity; the UI marks the others as "legacy".
func (a Algo) Cryptographic() bool {
	switch a {
	case SHA256, SHA512, BLAKE2b256, BLAKE3:
		return true
	}
	return false
}

// Size returns the digest length in bytes.
func (a Algo) Size() int {
	switch a {
	case CRC16, CRC16IBM:
		return 2
	case CRC32, CRC32C, Adler32:
		return 4
	case CRC64, XXH64:
		return 8
	case MD5:
		return 16
	case SHA1:
		return 20
	case SHA256, BLAKE2b256, BLAKE3:
		return 32
	case SHA512:
		return 64
	}
	return 0
}

// Parse resolves an algorithm name (case-insensitive, common aliases
// accepted) for CLI/API input.
func Parse(s string) (Algo, error) {
	up := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		up = append(up, c)
	}
	aliases := map[string]Algo{
		"CRC16": CRC16, "CRC16-CCITT": CRC16, "CCITT": CRC16,
		"CRC16-IBM": CRC16IBM, "CRC16-XMODEM": CRC16IBM,
		"CRC32": CRC32, "CRC32-IEEE": CRC32,
		"CRC32-C": CRC32C, "CRC32C": CRC32C, "CASTAGNOLI": CRC32C,
		"CRC64": CRC64, "CRC64-XZ": CRC64, "CRC64/GO": CRC64,
		"ADLER32": Adler32, "ADLER-32": Adler32,
		"MD5":  MD5,
		"SHA1": SHA1, "SHA-1": SHA1,
		"SHA256": SHA256, "SHA-256": SHA256,
		"SHA512": SHA512, "SHA-512": SHA512,
		"BLAKE2B": BLAKE2b256, "BLAKE2B-256": BLAKE2b256, "BLAKE2B256": BLAKE2b256,
		"BLAKE3":   BLAKE3,
		"XXHASH64": XXH64, "XXH64": XXH64, "XXHASH": XXH64,
	}
	if a, ok := aliases[string(up)]; ok {
		return a, nil
	}
	return "", fmt.Errorf("hash: unknown algorithm %q", s)
}

// New returns a hash.Hash for the algorithm.
func New(a Algo) (hash.Hash, error) {
	switch a {
	case CRC16:
		return newCRC16(0x1021, 0x0000, false, 0xFFFF), nil
	case CRC16IBM:
		return newCRC16(0xA001, 0x0000, true, 0x0000), nil
	case CRC32:
		return crc32.New(crc32.IEEETable), nil
	case CRC32C:
		return crc32.New(crc32.MakeTable(crc32.Castagnoli)), nil
	case CRC64:
		return crc64.New(crc64.MakeTable(crc64.ECMA)), nil
	case Adler32:
		return adler32.New(), nil
	case MD5:
		return md5.New(), nil
	case SHA1:
		return sha1.New(), nil
	case SHA256:
		return sha256.New(), nil
	case SHA512:
		return sha512.New(), nil
	case BLAKE2b256:
		return blake2b.New256(nil)
	case BLAKE3:
		return blake3.New(32, nil), nil
	case XXH64:
		return xxhash.New(), nil
	}
	return nil, fmt.Errorf("hash: unsupported algorithm %q", a)
}

// Sum computes the digest of data in one shot. All digests are returned in
// the byte order produced by their reference implementations (xxHash64 is
// big-endian, matching the canonical representation).
func Sum(a Algo, data []byte) ([]byte, error) {
	h, err := New(a)
	if err != nil {
		return nil, err
	}
	h.Write(data) // hash.Hash writes never fail
	return h.Sum(nil), nil
}

// Reader streams r through the algorithm and returns the digest. The optional
// progress callback receives the running byte count after every chunk; return
// false to cancel the operation (used by long scans on multi-GB images).
func Reader(a Algo, r io.Reader, progress func(total int64) bool) ([]byte, error) {
	h, err := New(a)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 4<<20)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			total += int64(n)
			if progress != nil && !progress(total) {
				return nil, fmt.Errorf("hash: canceled after %d bytes", total)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("hash: read: %w", err)
		}
	}
	return h.Sum(nil), nil
}

// Format renders a digest as hex (with an optional algorithm prefix, e.g.
// "SHA-256: 9f86d0…").
func Format(a Algo, sum []byte, prefix bool) string {
	if prefix {
		return fmt.Sprintf("%s: %x", a, sum)
	}
	return fmt.Sprintf("%x", sum)
}

// crc16Hash implements CRC-16 either LSB-first (reflected) or MSB-first.
type crc16Hash struct {
	poly      uint16 // already bit-reversed when reflected
	reflected bool
	init      uint16
	crc       uint16
	blockSize int
}

func newCRC16(poly, _ uint16, reflected bool, init uint16) hash.Hash {
	return &crc16Hash{poly: poly, reflected: reflected, init: init, crc: init, blockSize: 1}
}

func (c *crc16Hash) Write(p []byte) (int, error) {
	for _, b := range p {
		if c.reflected {
			c.crc ^= uint16(b)
			for i := 0; i < 8; i++ {
				if c.crc&1 != 0 {
					c.crc = c.crc>>1 ^ c.poly
				} else {
					c.crc >>= 1
				}
			}
		} else {
			c.crc ^= uint16(b) << 8
			for i := 0; i < 8; i++ {
				if c.crc&0x8000 != 0 {
					c.crc = c.crc<<1 ^ c.poly
				} else {
					c.crc <<= 1
				}
			}
		}
	}
	return len(p), nil
}

func (c *crc16Hash) Sum(b []byte) []byte {
	return append(b, byte(c.crc>>8), byte(c.crc))
}

func (c *crc16Hash) Reset()         { c.crc = c.init }
func (c *crc16Hash) Size() int      { return 2 }
func (c *crc16Hash) BlockSize() int { return c.blockSize }
