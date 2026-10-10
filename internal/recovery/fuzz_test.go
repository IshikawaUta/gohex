package recovery

import "testing"

// FuzzCarveScan runs the signature scanner over an arbitrary blob with every
// registered type enabled. The scanner may return any number of objects (or
// an error); what it must never do is panic or return results outside the
// scanned range.
func FuzzCarveScan(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("no files here, just text"))
	f.Add(fakeJPEG(300))
	f.Add(fakePNG(300))
	f.Add(fakeZIP(300))
	f.Add(fakeBMP(400))
	f.Add(concat(pad(100), fakeJPEG(128), pad(100), fakePNG(128)))
	f.Add([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}) // header only
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("input too large")
		}
		src := &memStream{data}
		got, err := Carve(src, Options{})
		if err != nil {
			return
		}
		for i, c := range got {
			if c.Offset < 0 || c.Length <= 0 || c.Offset+c.Length > int64(len(data)) {
				t.Fatalf("[%d] out-of-range result %+v", i, c)
			}
			if i > 0 && got[i-1].Offset > c.Offset {
				t.Fatalf("results out of order: %+v then %+v", got[i-1], c)
			}
		}
		// The truncated path must obey the same bounds.
		if _, err := Carve(src, Options{AllowTruncated: true, Max: 16}); err != nil {
			t.Fatalf("Carve(AllowTruncated): %v", err)
		}
	})
}
