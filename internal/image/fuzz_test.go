package image

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzImageProbe drives the container-format dispatcher the way ProbeImage
// does: magic detection over the file head, then the format's own opener.
// The formats delegated to qemu-img (QCOW2/VMDK/VHDX) only run through
// detect — their openers spawn an external process, which must not happen on
// fuzzed input.
func FuzzImageProbe(f *testing.F) {
	f.Add([]byte{})                                 // empty file
	f.Add([]byte("raw bytes with no magic at all")) // RAW fallback
	f.Add([]byte("EVF\x09\r\n\xff\x00" + "header")) // EWF/E01
	f.Add([]byte("LVF\x09\r\n\xff\x00" + "header")) // L01 logical evidence
	f.Add([]byte("conectix" + "\x00\x00"))          // VHD fixed footer cookie
	f.Add([]byte("vhdxfile" + "\x00"))              // VHDX
	f.Add([]byte("KDMV"))                           // VMDK sparse
	f.Add([]byte("# Disk DescriptorFile\n"))        // VMDK descriptor
	f.Add([]byte("QFI\xfb"))                        // QCOW2
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("input too large")
		}
		path := filepath.Join(t.TempDir(), "image.bin")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		head := data
		if len(head) > 512 {
			head = head[:512] // readHead returns at most 512 bytes
		}
		format, err := detect(head, path)
		if err != nil {
			return // unsupported container (EWF2) or unreadable tail
		}
		switch format {
		case FormatQCOW2, FormatVMDK, FormatVHDX:
			return // qemu-img delegation: detection only
		}
		r, err := Open(path)
		if err != nil {
			return
		}
		defer r.Close()
		_ = r.Format()
		var buf [64]byte
		_, _ = r.ReadAt(buf[:], 0)
		_, _ = r.ReadAt(buf[:], r.Size()-16)
	})
}

// FuzzOpenFormat fuzzes the forced-format entry point, which skips magic
// detection and exercises each opener on deliberately mislabelled bytes.
func FuzzOpenFormat(f *testing.F) {
	f.Add([]byte("conectix"), "vhd")
	f.Add([]byte("EVF\x09\r\n\xff\x00"), "ewf")
	f.Add([]byte("anything"), "raw")
	f.Add([]byte("anything"), "")
	f.Add([]byte("anything"), "nope")
	f.Fuzz(func(t *testing.T, data []byte, format string) {
		if len(data) > 1<<20 {
			t.Skip("input too large")
		}
		switch format {
		case FormatQCOW2, FormatVMDK, FormatVHDX:
			t.Skip("qemu-img delegation")
		}
		path := filepath.Join(t.TempDir(), "image.bin")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if r, err := OpenFormat(path, format); err == nil {
			_ = r.Format()
			r.Close()
		}
	})
}
