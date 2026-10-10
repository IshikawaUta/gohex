package hash

import (
	"bytes"
	"math/rand"
	"testing"
)

// BenchmarkSum4MiB hashes a 4 MiB buffer with the two recommended integrity
// algorithms, in one shot the way the checksum panel does for a selection.
func BenchmarkSum4MiB(b *testing.B) {
	data := make([]byte, 4<<20)
	rand.New(rand.NewSource(0xDEADBEEF)).Read(data)
	for _, a := range []Algo{SHA256, BLAKE3} {
		b.Run(string(a), func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				if _, err := Sum(a, data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkReader4MiB streams the same buffer through Reader, the path used
// for whole-image hashing with progress reporting.
func BenchmarkReader4MiB(b *testing.B) {
	data := make([]byte, 4<<20)
	rand.New(rand.NewSource(0xDEADBEEF)).Read(data)
	for _, a := range []Algo{SHA256, BLAKE3} {
		b.Run(string(a), func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				if _, err := Reader(a, bytes.NewReader(data), nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
