package recovery

import (
	"math/rand"
	"testing"
)

// benchBlob builds a ~4 MiB blob with a handful of embedded objects, the
// shape of a carved partition holding scattered files.
func benchBlob(size int) []byte {
	rnd := rand.New(rand.NewSource(0xBEEF))
	data := make([]byte, size)
	rnd.Read(data)
	// Overwrite the noise with padding the scanner treats as clean space so
	// the planted objects are the only candidates.
	for i := range data {
		if data[i] == 0 {
			data[i] = 0x20
		}
	}
	plants := [][]byte{
		fakeJPEG(1 << 16),
		fakePNG(1 << 16),
		fakeZIP(1 << 16),
		fakeBMP(1 << 16),
		fakeRIFF("WAVE", 1<<16),
		fakeMP4(32, (1<<16)-32),
	}
	step := len(data) / (len(plants) + 1)
	for i, p := range plants {
		off := (i + 1) * step
		if off+len(p) > len(data) {
			break
		}
		copy(data[off:], p)
	}
	return data
}

// BenchmarkCarveScan scans a 4 MiB blob with all types enabled; the
// "filtered" variant restricts the run to two types the way a user-chosen
// export does.
func BenchmarkCarveScan(b *testing.B) {
	data := benchBlob(4 << 20)
	src := &memStream{data}
	for _, bc := range []struct {
		name string
		opts Options
	}{
		{"all", Options{}},
		{"filtered", Options{Types: []string{"jpeg", "png"}}},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				if _, err := Carve(src, bc.opts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
