package fs

import (
	"testing"
)

// FuzzProbe drives the filesystem dispatcher with arbitrary bytes. Probe must
// simply not panic: an unrecognized range, a truncated boot sector or a
// corrupt FAT all legitimately produce an error.
func FuzzProbe(f *testing.F) {
	f.Add([]byte{})                                                       // empty range
	f.Add(make([]byte, 4096))                                             // zeros: right size, no magic
	f.Add(syntheticFAT(3))                                                // valid tiny FAT12 image
	f.Add(syntheticFAT(3)[:1024])                                         // truncated boot sector
	f.Add([]byte("NTFS    " + "\x00"))                                    // NTFS OEM name without a boot sector
	f.Add([]byte("\x55\xAAgarbage!!!"))                                   // boot signature only
	f.Add([]byte("This is not a filesystem at all, just prose.\x00\x00")) // garbage
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("input too large")
		}
		src := memReader{data}
		fs, err := Probe(src, 0, int64(len(data)))
		if err != nil {
			return // errors are fine; only panics matter
		}
		// When a filesystem was recognised, exercise its read paths too:
		// they parse on top of the same bytes.
		ents, err := fs.List("/")
		if err != nil {
			return
		}
		for _, e := range ents {
			if !e.Dir && e.Size >= 0 && e.Size < 1<<20 {
				buf := make([]byte, 64)
				_, _ = fs.ReadAt(e.Path, 0, buf)
			}
		}
	})
}

// FuzzProbeOffset fuzzes the partition-range variant of the dispatcher with a
// non-zero offset and a length that may run past the source.
func FuzzProbeOffset(f *testing.F) {
	img := syntheticFAT(3)
	f.Add(img, int64(0), int64(len(img)))
	f.Add(img, int64(512), int64(4096))
	f.Add(img, int64(1<<40), int64(-1))
	f.Add(img, int64(-5), int64(1<<20))
	f.Add(make([]byte, 8192), int64(4096), int64(4096))
	f.Fuzz(func(t *testing.T, data []byte, offset, length int64) {
		if len(data) > 1<<20 {
			t.Skip("input too large")
		}
		if offset > 1<<30 || length > 1<<30 {
			t.Skip("range too large")
		}
		_, _ = Probe(memReader{data}, offset, length)
	})
}
