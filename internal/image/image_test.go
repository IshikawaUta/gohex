package image

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pattern returns a deterministic byte pattern.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*197 + (i>>11)*31) ^ (i >> 3))
	}
	return b
}

func writeImg(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func readRange(t *testing.T, r Reader, off int64, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	got := 0
	for got < n {
		k, err := r.ReadAt(buf[got:], off+int64(got))
		got += k
		if err != nil {
			if errors.Is(err, io.EOF) && got == n {
				break
			}
			t.Fatalf("ReadAt(off=%d, n=%d) after %d bytes: %v", off, n, got, err)
		}
		if k == 0 {
			t.Fatalf("ReadAt(off=%d, n=%d) made no progress", off, n)
		}
	}
	if got != n {
		t.Fatalf("ReadAt(off=%d, n=%d) returned %d bytes", off, n, got)
	}
	return buf
}

// checkBounds exercises the shared end-of-medium and negative-offset contract.
func checkBounds(t *testing.T, r Reader) {
	t.Helper()
	size := r.Size()
	if size <= 0 {
		t.Fatalf("Size() = %d", size)
	}
	buf := make([]byte, 16)
	if n, err := r.ReadAt(buf, size); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("ReadAt at Size(): got (%d, %v), want (0, EOF)", n, err)
	}
	if n, err := r.ReadAt(buf, -1); n != 0 || err == nil {
		t.Errorf("ReadAt at -1: got (%d, %v), want (0, error)", n, err)
	}
	if n, err := r.ReadAt(buf, size+100); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("ReadAt past Size(): got (%d, %v), want (0, EOF)", n, err)
	}
	tail := make([]byte, 8)
	if n, err := r.ReadAt(tail, size-8); n != 8 || err != nil {
		t.Errorf("ReadAt last 8 bytes: got (%d, %v), want (8, nil)", n, err)
	}
	if n, err := r.ReadAt(buf, size-8); n != 8 || !errors.Is(err, io.EOF) {
		t.Errorf("ReadAt overrun: got (%d, %v), want (8, EOF)", n, err)
	}
}

func requireQemu(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed")
	}
}

func qemuConvert(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("qemu-img", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("qemu-img %v: %v\n%s", args, err, out)
	}
}

// ---------------------------------------------------------------- detection

func TestDetectMagic(t *testing.T) {
	dummy := writeImg(t, "dummy", make([]byte, 4096))
	for _, tc := range []struct {
		name    string
		head    []byte
		want    string
		wantErr string
	}{
		{"ewf", append([]byte(ewfSignature), 1, 0, 1, 0, 0), FormatEWF, ""},
		{"ex01", []byte("EVF2\r\n\x81\x00"), "", "EWF2 (Ex01)"},
		{"l01", []byte("LVF\x09\r\n\xff\x00"), FormatL01, ""},
		{"l01-mvf", []byte("MVF\x09\r\n\xff\x00"), FormatL01, ""},
		{"qcow2", []byte("QFI\xfb\x00\x00\x00\x03"), FormatQCOW2, ""},
		{"vmdk-sparse", []byte("KDMV\x01\x00\x00\x00"), FormatVMDK, ""},
		{"vmdk-desc", []byte("# Disk DescriptorFile\n"), FormatVMDK, ""},
		{"vhdx", []byte("vhdxfile\x00\x00\x00\x00"), FormatVHDX, ""},
		{"vhd-fixed", []byte("conectix\x00\x00\x00\x02"), FormatVHD, ""},
		{"vhd-dynamic", []byte("cxsparse\x00\x00\x00\x01"), FormatVHD, ""},
		{"zeros", make([]byte, 512), FormatRaw, ""},
		{"short-head", []byte("QF"), FormatRaw, ""},
		{"empty", nil, FormatRaw, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := detect(tc.head, dummy)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("detect = (%q, %v), want error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("detect = (%q, %v), want (%q, nil)", got, err, tc.want)
			}
		})
	}
}

func TestDetectFallsBackToRawOnSmallFile(t *testing.T) {
	p := writeImg(t, "tiny.bin", []byte("no known magic at all"))
	format, err := detect([]byte("no known magic at all"), p)
	if err != nil || format != FormatRaw {
		t.Fatalf("detect = (%q, %v), want raw", format, err)
	}
}

func TestReadHeadAndTailErrors(t *testing.T) {
	if _, err := readHead(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("readHead on missing file: want error")
	}
	if _, err := readTail(filepath.Join(t.TempDir(), "missing"), 512); err == nil {
		t.Error("readTail on missing file: want error")
	}
	if _, err := readTail(writeImg(t, "short.bin", make([]byte, 10)), 512); err == nil {
		t.Error("readTail smaller than window: want error")
	}
}

// -------------------------------------------------------------------- raw

func TestOpenRaw(t *testing.T) {
	data := pattern(1 << 20)
	r, err := Open(writeImg(t, "disk.img", data))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if r.Format() != FormatRaw {
		t.Fatalf("Format() = %q, want raw", r.Format())
	}
	if r.Size() != int64(len(data)) {
		t.Fatalf("Size() = %d, want %d", r.Size(), len(data))
	}
	if got := readRange(t, r, 0, len(data)); !bytes.Equal(got, data) {
		t.Fatal("full read does not match the source image")
	}
	if got := readRange(t, r, 1000, 100); !bytes.Equal(got, data[1000:1100]) {
		t.Fatal("mid-file read mismatch")
	}
	checkBounds(t, r)
}

func TestOpenErrors(t *testing.T) {
	dir := t.TempDir()
	raw := writeImg(t, "disk.img", pattern(4096))

	if _, err := Open(filepath.Join(dir, "nope.img")); err == nil || !strings.Contains(err.Error(), "image:") {
		t.Errorf("Open(missing) = %v, want image-prefixed error", err)
	}
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Errorf("Open(directory) = %v, want directory error", err)
	}
	if _, err := OpenFormat(raw, ""); err == nil || !strings.Contains(err.Error(), "empty format") {
		t.Errorf("OpenFormat(\"\") = %v, want empty format error", err)
	}
	if _, err := OpenFormat(raw, "bogus"); err == nil || !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("OpenFormat(bogus) = %v, want unknown format error", err)
	}
	if _, err := OpenFormat(raw, FormatEWF); err == nil || !strings.Contains(err.Error(), "image/ewf") {
		t.Errorf("OpenFormat(raw, ewf) = %v, want image/ewf error", err)
	}
	if _, err := OpenFormat(raw, FormatVHD); err == nil || !strings.Contains(err.Error(), "image/vhd") {
		t.Errorf("OpenFormat(raw, vhd) = %v, want image/vhd error", err)
	}
}

func TestOpenUnsupportedContainerFamilies(t *testing.T) {
	p := writeImg(t, "ex01", []byte("EVF2\r\n\x81\x00\x01\x00\x01\x00\x00"))
	_, err := Open(p)
	if err == nil || !strings.Contains(err.Error(), "roadmap stage 3") {
		t.Errorf("Open(ex01) = %v, want roadmap stage 3 error", err)
	}
}

// ------------------------------------------------------------------- qemu

func TestQemuFlatten(t *testing.T) {
	requireQemu(t)
	data := pattern(2 << 20)
	src := writeImg(t, "src.raw", data)

	for _, format := range []string{FormatQCOW2, FormatVMDK, FormatVHDX} {
		t.Run(format, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "disk."+format)
			qemuConvert(t, "convert", "-f", "raw", "-O", format, src, dst)

			r, err := Open(dst)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()

			if r.Format() != format {
				t.Fatalf("Format() = %q, want %q", r.Format(), format)
			}
			if r.Size() != int64(len(data)) {
				t.Fatalf("Size() = %d, want %d", r.Size(), len(data))
			}
			if got := readRange(t, r, 0, len(data)); !bytes.Equal(got, data) {
				t.Fatal("flattened image does not match the source")
			}
			checkBounds(t, r)
		})
	}
}

func TestQemuDetectIgnoresExtension(t *testing.T) {
	requireQemu(t)
	src := writeImg(t, "src.raw", pattern(1<<20))
	dst := filepath.Join(t.TempDir(), "looks-raw.img")
	qemuConvert(t, "convert", "-f", "raw", "-O", FormatQCOW2, src, dst)

	r, err := Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Format() != FormatQCOW2 {
		t.Fatalf("Format() = %q, want qcow2", r.Format())
	}
}

func TestQemuMissing(t *testing.T) {
	requireQemu(t)
	src := writeImg(t, "src.raw", pattern(1<<20))
	dst := filepath.Join(t.TempDir(), "disk.qcow2")
	qemuConvert(t, "convert", "-f", "raw", "-O", FormatQCOW2, src, dst)

	t.Setenv("PATH", t.TempDir())
	_, err := Open(dst)
	if err == nil || !strings.Contains(err.Error(), "qemu-img") {
		t.Fatalf("Open without qemu-img = %v, want mention of qemu-img", err)
	}
}

func TestQemuCorruptImage(t *testing.T) {
	requireQemu(t)
	p := writeImg(t, "broken.qcow2", append([]byte("QFI\xfb\x00\x00\x00\x03"), pattern(4096)...))
	_, err := OpenFormat(p, FormatQCOW2)
	if err == nil || !strings.Contains(err.Error(), "qemu-img convert") {
		t.Fatalf("Open(corrupt qcow2) = %v, want qemu-img convert error", err)
	}
}

// -------------------------------------------------------------------- vhd

// vhdChecksum is the footer checksum: the ones-complement of the byte sum,
// skipping the checksum field itself (bytes 64..67).
func vhdChecksum(footer []byte) uint32 {
	var sum uint32
	for i, b := range footer {
		if i >= 64 && i < 68 {
			continue
		}
		sum += uint32(b)
	}
	return ^sum
}

func vhdFooter(cur uint64, diskType uint32, dataOffset uint64) []byte {
	f := make([]byte, vhdFooterSize)
	copy(f, vhdCookie)
	binary.BigEndian.PutUint32(f[8:], 2)           // features
	binary.BigEndian.PutUint32(f[12:], 0x00010000) // file format version
	binary.BigEndian.PutUint64(f[16:], dataOffset)
	binary.BigEndian.PutUint64(f[40:], cur) // original size
	binary.BigEndian.PutUint64(f[48:], cur) // current size
	binary.BigEndian.PutUint32(f[60:], diskType)
	copy(f[68:], []byte("gohex test"))
	binary.BigEndian.PutUint32(f[64:], vhdChecksum(f))
	return f
}

// buildFixedVHD lays out the Microsoft fixed-disk layout: leading footer,
// payload, trailing footer.
func buildFixedVHD(data []byte) []byte {
	f := vhdFooter(uint64(len(data)), vhdTypeFixed, 0xFFFFFFFFFFFFFFFF)
	out := make([]byte, 0, 2*vhdFooterSize+len(data))
	out = append(out, f...)
	out = append(out, data...)
	out = append(out, f...)
	return out
}

// buildDynamicVHD lays out a dynamic disk with one allocated and one
// unallocated block, so zero-filling gets covered. Allocated blocks carry
// the sector bitmap that the format puts ahead of the payload.
func buildDynamicVHD(block0 []byte, blockSize int64, allocate []bool) []byte {
	n := len(allocate)
	footer := vhdFooter(uint64(int64(n)*blockSize), vhdTypeDynamic, vhdFooterSize)
	batOff := int64(1536)
	blocksStart := int64(4096)

	bitmap := ((blockSize/4096 + 511) / 512) * 512
	if bitmap < 512 {
		bitmap = 512
	}
	region := bitmap + blockSize

	hdr := make([]byte, 1024)
	copy(hdr, vhdDynCookie)
	binary.BigEndian.PutUint64(hdr[16:], uint64(batOff))
	binary.BigEndian.PutUint32(hdr[24:], 0x00010000)
	binary.BigEndian.PutUint32(hdr[28:], uint32(n))
	binary.BigEndian.PutUint32(hdr[32:], uint32(blockSize))

	fileSize := blocksStart + int64(n)*region + vhdFooterSize
	out := make([]byte, fileSize)
	copy(out[0:], footer)
	copy(out[vhdFooterSize:], hdr)

	bat := make([]byte, n*4)
	for i := 0; i < n; i++ {
		off := blocksStart + int64(i)*region
		if !allocate[i] {
			binary.BigEndian.PutUint32(bat[i*4:], 0xFFFFFFFF)
			continue
		}
		binary.BigEndian.PutUint32(bat[i*4:], uint32(off/512))
		for k := int64(0); k < bitmap; k++ {
			out[off+k] = 0xFF // every sector of the block holds valid data
		}
		if i == 0 {
			copy(out[off+bitmap:], block0)
		}
	}
	copy(out[batOff:], bat)
	copy(out[fileSize-vhdFooterSize:], footer)
	return out
}

func TestVHDFixedMicrosoftLayout(t *testing.T) {
	data := pattern(1 << 20)
	r, err := Open(writeImg(t, "fixed.vhd", buildFixedVHD(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if r.Format() != FormatVHD {
		t.Fatalf("Format() = %q, want vhd", r.Format())
	}
	if r.Size() != int64(len(data)) {
		t.Fatalf("Size() = %d, want %d", r.Size(), len(data))
	}
	if got := readRange(t, r, 0, len(data)); !bytes.Equal(got, data) {
		t.Fatal("fixed VHD payload mismatch")
	}
	checkBounds(t, r)
}

func TestVHDDynamicWithUnallocatedBlock(t *testing.T) {
	const bs = 1 << 20
	block0 := pattern(bs)
	r, err := Open(writeImg(t, "dynamic.vhd", buildDynamicVHD(block0, bs, []bool{true, false})))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if r.Size() != 2*bs {
		t.Fatalf("Size() = %d, want %d", r.Size(), 2*bs)
	}
	if got := readRange(t, r, 0, bs); !bytes.Equal(got, block0) {
		t.Fatal("allocated block mismatch")
	}
	if got := readRange(t, r, bs, bs); !bytes.Equal(got, make([]byte, bs)) {
		t.Fatal("unallocated block must read as zeroes")
	}
	span := readRange(t, r, int64(bs)-8, 16)
	if !bytes.Equal(span[:8], block0[bs-8:]) || !bytes.Equal(span[8:], make([]byte, 8)) {
		t.Fatal("boundary-spanning read mismatch")
	}
	checkBounds(t, r)
}

func TestVHDDetectByTrailingFooter(t *testing.T) {
	// qemu writes fixed VHDs without the Microsoft leading footer, so the
	// only clue is the trailing one.
	requireQemu(t)
	data := pattern(1 << 20)
	src := writeImg(t, "src.raw", data)
	dst := filepath.Join(t.TempDir(), "fixed.vhd")
	qemuConvert(t, "convert", "-f", "raw", "-O", "vpc", "-o", "subformat=fixed", src, dst)

	r, err := Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Format() != FormatVHD {
		t.Fatalf("Format() = %q, want vhd", r.Format())
	}
	if r.Size() < int64(len(data)) {
		t.Fatalf("Size() = %d, want at least %d", r.Size(), len(data))
	}
	if got := readRange(t, r, 0, len(data)); !bytes.Equal(got, data) {
		t.Fatal("qemu fixed VHD payload mismatch")
	}
}

func TestVHDDynamicCrossCheck(t *testing.T) {
	requireQemu(t)
	data := pattern(1 << 20)
	src := writeImg(t, "src.raw", data)
	dst := filepath.Join(t.TempDir(), "dynamic.vhd")
	qemuConvert(t, "convert", "-f", "raw", "-O", "vpc", src, dst)

	r, err := Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Format() != FormatVHD {
		t.Fatalf("Format() = %q, want vhd", r.Format())
	}
	if r.Size() < int64(len(data)) {
		t.Fatalf("Size() = %d, want at least %d", r.Size(), len(data))
	}
	if got := readRange(t, r, 0, len(data)); !bytes.Equal(got, data) {
		t.Fatal("qemu dynamic VHD payload mismatch")
	}
}

func TestVHDErrors(t *testing.T) {
	t.Run("too-small", func(t *testing.T) {
		p := writeImg(t, "tiny.vhd", make([]byte, 100))
		_, err := OpenFormat(p, FormatVHD)
		if err == nil || !strings.Contains(err.Error(), "too small") {
			t.Fatalf("err = %v, want too-small error", err)
		}
	})
	t.Run("no-cookie", func(t *testing.T) {
		p := writeImg(t, "nocookie.vhd", make([]byte, 2048))
		_, err := OpenFormat(p, FormatVHD)
		if err == nil || !strings.Contains(err.Error(), "conectix") {
			t.Fatalf("err = %v, want missing cookie error", err)
		}
	})
	t.Run("differencing", func(t *testing.T) {
		data := pattern(512)
		f := vhdFooter(uint64(len(data)), vhdTypeDifferencing, vhdFooterSize)
		p := writeImg(t, "diff.vhd", append(append(f, data...), f...))
		_, err := OpenFormat(p, FormatVHD)
		if err == nil || !strings.Contains(err.Error(), "differencing") {
			t.Fatalf("err = %v, want differencing error", err)
		}
	})
	t.Run("unknown-disk-type", func(t *testing.T) {
		data := pattern(512)
		f := vhdFooter(uint64(len(data)), 9, vhdFooterSize)
		p := writeImg(t, "weird.vhd", append(append(f, data...), f...))
		_, err := OpenFormat(p, FormatVHD)
		if err == nil || !strings.Contains(err.Error(), "unknown disk type 9") {
			t.Fatalf("err = %v, want unknown disk type error", err)
		}
	})
	t.Run("truncated-fixed", func(t *testing.T) {
		full := buildFixedVHD(pattern(1 << 20))
		p := writeImg(t, "cut.vhd", full[:len(full)-600])
		_, err := OpenFormat(p, FormatVHD)
		if err == nil || !strings.Contains(err.Error(), "truncated") {
			t.Fatalf("err = %v, want truncated error", err)
		}
	})
	t.Run("payload-short-of-footer", func(t *testing.T) {
		// A fixed footer claiming 1 MiB over a file that cannot hold it.
		broken := vhdFooter(1<<20, vhdTypeFixed, 0xFFFFFFFFFFFFFFFF)
		broken[0] = 'X' // no leading cookie, so the trailing one rules
		good := vhdFooter(1<<20, vhdTypeFixed, 0xFFFFFFFFFFFFFFFF)
		buf := append(append(append([]byte{}, broken...), make([]byte, 1024)...), good...)
		_, err := OpenFormat(writeImg(t, "half.vhd", buf), FormatVHD)
		if err == nil || !strings.Contains(err.Error(), "truncated") {
			t.Fatalf("err = %v, want truncated error", err)
		}
	})
	t.Run("negative-size", func(t *testing.T) {
		data := pattern(512)
		f := vhdFooter(0, vhdTypeFixed, 0xFFFFFFFFFFFFFFFF)
		binary.BigEndian.PutUint64(f[48:], 1<<63) // int64 sign bit set
		binary.BigEndian.PutUint32(f[64:], vhdChecksum(f))
		p := writeImg(t, "neg.vhd", append(append(f, data...), f...))
		_, err := OpenFormat(p, FormatVHD)
		if err == nil || !strings.Contains(err.Error(), "negative virtual size") {
			t.Fatalf("err = %v, want negative size error", err)
		}
	})
}

func TestVHDDynamicErrors(t *testing.T) {
	const bs = 1 << 20
	good := buildDynamicVHD(pattern(bs), bs, []bool{true, false})

	for _, tc := range []struct {
		name    string
		mutate  func(b []byte)
		wantErr string
	}{
		{"bad-block-size", func(b []byte) {
			binary.BigEndian.PutUint32(b[vhdFooterSize+32:], 1000)
		}, "invalid block size"},
		{"too-many-blocks", func(b []byte) {
			binary.BigEndian.PutUint32(b[vhdFooterSize+28:], 1)
		}, "exceeds table entries"},
		{"bat-past-eof", func(b []byte) {
			binary.BigEndian.PutUint64(b[vhdFooterSize+16:], uint64(len(b)+4096))
		}, "block allocation table"},
		{"bad-bat-entry", func(b []byte) {
			binary.BigEndian.PutUint32(b[1536:], 0x7FFFFFFF)
		}, "points outside"},
		{"missing-dyn-cookie", func(b []byte) {
			copy(b[vhdFooterSize:], "notcxspar")
		}, "dynamic header cookie"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), good...)
			tc.mutate(b)
			_, err := OpenFormat(writeImg(t, "bad.vhd", b), FormatVHD)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

// -------------------------------------------------------------------- ewf

type ewfLayout struct {
	volPos, secPos, tblPos, donePos int64
	volPayload, entries             int64
	n                               int
	big                             bool
}

// ewfChunks splits data into stored chunks: chunk 1 stays uncompressed so
// that code path gets exercised.
func ewfChunks(t *testing.T, data []byte) (stored [][]byte, compressed []bool) {
	t.Helper()
	const bps, spc = 512, 64
	cs := bps * spc
	if len(data) == 0 || len(data)%bps != 0 {
		t.Fatalf("payload length %d must be a positive multiple of %d", len(data), bps)
	}
	n := (len(data) + cs - 1) / cs
	stored = make([][]byte, n)
	compressed = make([]bool, n)
	for i := 0; i < n; i++ {
		s, e := i*cs, (i+1)*cs
		if e > len(data) {
			e = len(data)
		}
		payload := data[s:e]
		if i == 1 && n > 2 {
			stored[i] = append(append([]byte{}, payload...), 0, 0, 0, 0)
			continue
		}
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		if _, err := zw.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		stored[i] = buf.Bytes()
		compressed[i] = true
	}
	return stored, compressed
}

// buildE01 writes a single-segment E01 image in the requested byte order,
// with the chunks held in a "sectors" section ahead of their table.
func buildE01(t *testing.T, data []byte, big bool) ([]byte, ewfLayout) {
	t.Helper()
	const bps, spc = 512, 64
	stored, compressed := ewfChunks(t, data)
	n := len(stored)
	sectors := uint64(len(data) / bps)

	put32 := func(b []byte, v uint32) {
		if big {
			binary.BigEndian.PutUint32(b, v)
		} else {
			binary.LittleEndian.PutUint32(b, v)
		}
	}
	put64 := func(b []byte, v uint64) {
		if big {
			binary.BigEndian.PutUint64(b, v)
		} else {
			binary.LittleEndian.PutUint64(b, v)
		}
	}
	desc := func(typ string, next, size int64) []byte {
		d := make([]byte, ewfDescSize)
		copy(d, typ)
		put64(d[16:], uint64(next))
		put64(d[24:], uint64(size))
		return d
	}

	l := ewfLayout{volPos: ewfHeaderSize, n: n, big: big}
	l.volPayload = l.volPos + ewfDescSize
	volSize := int64(ewfDescSize + 1052) // EnCase-style volume payload
	l.secPos = l.volPos + volSize

	secSize := int64(ewfDescSize)
	for _, s := range stored {
		secSize += int64(len(s))
	}
	l.tblPos = l.secPos + secSize
	tblSize := int64(ewfDescSize + ewfTableHdr + 4*n)
	l.entries = l.tblPos + ewfDescSize + ewfTableHdr
	l.donePos = l.tblPos + tblSize

	img := make([]byte, l.donePos+ewfDescSize)
	copy(img, ewfSignature)
	img[8] = 0x01

	copy(img[l.volPos:], desc("volume", l.secPos, volSize))
	vp := img[l.volPayload:]
	vp[0] = 1
	put32(vp[4:], uint32(n))
	put32(vp[8:], spc)
	put32(vp[12:], bps)
	put64(vp[16:], sectors)
	vp[52] = 1 // compression level

	copy(img[l.secPos:], desc("sectors", l.tblPos, secSize))
	off := l.secPos + ewfDescSize
	chunkOff := make([]int64, n)
	for i, s := range stored {
		chunkOff[i] = off
		copy(img[off:], s)
		off += int64(len(s))
	}

	copy(img[l.tblPos:], desc("table", l.donePos, tblSize))
	th := img[l.tblPos+ewfDescSize:]
	put32(th[0:], uint32(n))
	for i := 0; i < n; i++ {
		v := uint32(chunkOff[i])
		if compressed[i] {
			v |= ewfCompressMSB
		}
		put32(th[ewfTableHdr+i*4:], v)
	}

	copy(img[l.donePos:], desc("done", l.donePos, 0))
	return img, l
}

// buildE01Embedded writes a SMART/EnCase-1 style segment whose chunks live
// inside the table section itself: there is no "sectors" section at all.
func buildE01Embedded(t *testing.T, data []byte, big bool) []byte {
	t.Helper()
	const bps, spc = 512, 64
	stored, compressed := ewfChunks(t, data)
	n := len(stored)
	sectors := uint64(len(data) / bps)

	put32 := func(b []byte, v uint32) {
		if big {
			binary.BigEndian.PutUint32(b, v)
		} else {
			binary.LittleEndian.PutUint32(b, v)
		}
	}
	put64 := func(b []byte, v uint64) {
		if big {
			binary.BigEndian.PutUint64(b, v)
		} else {
			binary.LittleEndian.PutUint64(b, v)
		}
	}
	desc := func(typ string, next, size int64) []byte {
		d := make([]byte, ewfDescSize)
		copy(d, typ)
		put64(d[16:], uint64(next))
		put64(d[24:], uint64(size))
		return d
	}

	volPos := int64(ewfHeaderSize)
	volPayload := volPos + ewfDescSize
	volSize := int64(ewfDescSize + 1052)
	tblPos := volPos + volSize

	storedLen := int64(0)
	for _, s := range stored {
		storedLen += int64(len(s))
	}
	tblSize := int64(ewfDescSize+ewfTableHdr+4*n) + storedLen
	donePos := tblPos + tblSize

	img := make([]byte, donePos+ewfDescSize)
	copy(img, ewfSignature)
	img[8] = 0x01

	copy(img[volPos:], desc("volume", tblPos, volSize))
	vp := img[volPayload:]
	vp[0] = 1
	put32(vp[4:], uint32(n))
	put32(vp[8:], spc)
	put32(vp[12:], bps)
	put64(vp[16:], sectors)

	copy(img[tblPos:], desc("table", donePos, tblSize))
	th := img[tblPos+ewfDescSize:]
	put32(th[0:], uint32(n))

	chunkOff := tblPos + ewfDescSize + ewfTableHdr + int64(4*n)
	for i, s := range stored {
		v := uint32(chunkOff)
		if compressed[i] {
			v |= ewfCompressMSB
		}
		put32(th[ewfTableHdr+i*4:], v)
		copy(img[chunkOff:], s)
		chunkOff += int64(len(s))
	}

	copy(img[donePos:], desc("done", donePos, 0))
	return img
}

func ewfPayload(sectors int) []byte { return pattern(sectors * 512) }

func TestEWFReadback(t *testing.T) {
	for _, big := range []bool{false, true} {
		name := "little-endian"
		if big {
			name = "big-endian"
		}
		t.Run(name, func(t *testing.T) {
			data := ewfPayload(160) // 3 chunks of 32 KiB, last one partial
			r, err := Open(writeImg(t, "image.E01", mustBuild(t, data, big)))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()

			if r.Format() != FormatEWF {
				t.Fatalf("Format() = %q, want ewf", r.Format())
			}
			if r.Size() != int64(len(data)) {
				t.Fatalf("Size() = %d, want %d", r.Size(), len(data))
			}
			if got := readRange(t, r, 0, len(data)); !bytes.Equal(got, data) {
				t.Fatal("E01 payload mismatch")
			}
			if got := readRange(t, r, 32766, 8); !bytes.Equal(got, data[32766:32774]) {
				t.Fatal("cross-chunk read mismatch")
			}
			if got := readRange(t, r, 32768+32766, 8); !bytes.Equal(got, data[65534:65542]) {
				t.Fatal("uncompressed chunk boundary read mismatch")
			}
			checkBounds(t, r)
		})
	}
}

func mustBuild(t *testing.T, data []byte, big bool) []byte {
	t.Helper()
	img, _ := buildE01(t, data, big)
	return img
}

func TestEWFEmbeddedChunks(t *testing.T) {
	data := ewfPayload(160)
	r, err := Open(writeImg(t, "smart.E01", buildE01Embedded(t, data, false)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Size() != int64(len(data)) {
		t.Fatalf("Size() = %d, want %d", r.Size(), len(data))
	}
	if got := readRange(t, r, 0, len(data)); !bytes.Equal(got, data) {
		t.Fatal("embedded-chunk E01 payload mismatch")
	}
	checkBounds(t, r)
}

func TestEWFConcurrentReads(t *testing.T) {
	data := ewfPayload(160)
	r, err := Open(writeImg(t, "conc.E01", mustBuild(t, data, false)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			buf := make([]byte, 4096)
			for j := 0; j < 32; j++ {
				off := int64((j*7919)%len(data)) &^ 4095
				if _, err := r.ReadAt(buf, off); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

// minimalEWF writes only a segment header plus one section descriptor.
func minimalEWF(t *testing.T, typ string, next, size int64) string {
	t.Helper()
	img := make([]byte, ewfHeaderSize+ewfDescSize)
	copy(img, ewfSignature)
	img[8] = 0x01
	d := img[ewfHeaderSize:]
	copy(d, typ)
	binary.LittleEndian.PutUint64(d[16:], uint64(next))
	binary.LittleEndian.PutUint64(d[24:], uint64(size))
	return writeImg(t, "mini.E01", img)
}

func TestEWFHeaderErrors(t *testing.T) {
	t.Run("short-header", func(t *testing.T) {
		p := writeImg(t, "short.E01", []byte(ewfSignature[:5]))
		_, err := OpenFormat(p, FormatEWF)
		if err == nil || !strings.Contains(err.Error(), "segment header") {
			t.Fatalf("err = %v, want segment header error", err)
		}
	})
	t.Run("bad-signature", func(t *testing.T) {
		p := writeImg(t, "badsig.E01", append(make([]byte, 64), pattern(64)...))
		_, err := OpenFormat(p, FormatEWF)
		if err == nil || !strings.Contains(err.Error(), "segment signature") {
			t.Fatalf("err = %v, want signature error", err)
		}
	})
	t.Run("bad-fields-marker", func(t *testing.T) {
		img := append([]byte(ewfSignature), 0x02, 0, 1, 0, 0)
		_, err := OpenFormat(writeImg(t, "fields.E01", img), FormatEWF)
		if err == nil || !strings.Contains(err.Error(), "fields marker") {
			t.Fatalf("err = %v, want fields marker error", err)
		}
	})
	t.Run("bad-trailing-marker", func(t *testing.T) {
		img := append([]byte(ewfSignature), 0x01, 0, 1, 1, 0)
		_, err := OpenFormat(writeImg(t, "trail.E01", img), FormatEWF)
		if err == nil || !strings.Contains(err.Error(), "trailing fields marker") {
			t.Fatalf("err = %v, want trailing marker error", err)
		}
	})
	t.Run("only-done", func(t *testing.T) {
		_, err := OpenFormat(minimalEWF(t, "done", ewfHeaderSize, 0), FormatEWF)
		if err == nil || !strings.Contains(err.Error(), "no volume section") {
			t.Fatalf("err = %v, want no volume section error", err)
		}
	})
	t.Run("zero-next", func(t *testing.T) {
		_, err := OpenFormat(minimalEWF(t, "volume", 0, 0), FormatEWF)
		if err == nil || !strings.Contains(err.Error(), "bad next offset") {
			t.Fatalf("err = %v, want bad next offset error", err)
		}
	})
}

func TestEWFVolumeErrors(t *testing.T) {
	// Volume geometry that is nonsense in both byte orders.
	img := make([]byte, ewfHeaderSize+ewfDescSize+24+ewfDescSize)
	copy(img, ewfSignature)
	img[8] = 0x01
	d := img[ewfHeaderSize:]
	copy(d, "volume")
	binary.LittleEndian.PutUint64(d[16:], ewfHeaderSize+ewfDescSize+24)
	binary.LittleEndian.PutUint64(d[24:], ewfDescSize+24)
	done := img[ewfHeaderSize+ewfDescSize+24:]
	copy(done, "done")
	binary.LittleEndian.PutUint64(done[16:], ewfHeaderSize+ewfDescSize+24)

	_, err := OpenFormat(writeImg(t, "badvol.E01", img), FormatEWF)
	if err == nil || !strings.Contains(err.Error(), "volume geometry") {
		t.Fatalf("err = %v, want volume geometry error", err)
	}
}

func TestEWFTableErrors(t *testing.T) {
	data := ewfPayload(160)
	base, l := buildE01(t, data, false)

	for _, tc := range []struct {
		name    string
		mutate  func(img []byte)
		wantErr string
	}{
		{"byte-order-unresolvable", func(img []byte) {
			binary.LittleEndian.PutUint32(img[l.entries:], 0)
		}, "byte order"},
		{"too-few-chunks", func(img []byte) {
			binary.LittleEndian.PutUint64(img[l.volPayload+16:], 640)
		}, "chunks but the media needs"},
		{"implausible-count", func(img []byte) {
			binary.LittleEndian.PutUint32(img[l.tblPos+ewfDescSize:], 0)
		}, "chunk count"},
		{"count-past-eof", func(img []byte) {
			binary.LittleEndian.PutUint32(img[l.tblPos+ewfDescSize:], 1<<20+1)
		}, "chunk count"},
		{"entries-past-eof", func(img []byte) {
			binary.LittleEndian.PutUint32(img[l.tblPos+ewfDescSize:], 1<<19)
		}, "table entries beyond end"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := append([]byte(nil), base...)
			tc.mutate(img)
			_, err := OpenFormat(writeImg(t, "bad.E01", img), FormatEWF)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}

	t.Run("truncated-chain", func(t *testing.T) {
		img := append([]byte(nil), base[:l.tblPos+ewfDescSize]...)
		_, err := OpenFormat(writeImg(t, "cut.E01", img), FormatEWF)
		if err == nil || !strings.Contains(err.Error(), "bad next offset") {
			t.Fatalf("err = %v, want bad next offset error", err)
		}
	})
}

func TestEWFChunkOffsetErrors(t *testing.T) {
	data := ewfPayload(160)
	base, l := buildE01(t, data, false)

	t.Run("offset-past-end", func(t *testing.T) {
		img := append([]byte(nil), base...)
		binary.LittleEndian.PutUint32(img[l.entries:], uint32(len(img)-4))
		_, err := OpenFormat(writeImg(t, "off.E01", img), FormatEWF)
		if err == nil || !strings.Contains(err.Error(), "byte order") {
			t.Fatalf("err = %v, want byte order error", err)
		}
	})
	t.Run("non-monotonic-entries", func(t *testing.T) {
		img := append([]byte(nil), base...)
		e0 := binary.LittleEndian.Uint32(img[l.entries:])
		e1 := binary.LittleEndian.Uint32(img[l.entries+4:])
		binary.LittleEndian.PutUint32(img[l.entries:], e1|ewfCompressMSB)
		binary.LittleEndian.PutUint32(img[l.entries+4:], e0|ewfCompressMSB)
		_, err := OpenFormat(writeImg(t, "swap.E01", img), FormatEWF)
		if err != nil && !strings.Contains(err.Error(), "byte order") {
			t.Fatalf("err = %v, want success or byte order error", err)
		}
	})
}

func TestEWFUnusableChunk(t *testing.T) {
	data := ewfPayload(160)
	base, l := buildE01(t, data, false)
	img := append([]byte(nil), base...)
	// Wipe the stored payloads: offsets stay plausible, content does not.
	for i := l.secPos + ewfDescSize; i < l.tblPos; i++ {
		img[i] = 0
	}
	r, err := OpenFormat(writeImg(t, "zeroed.E01", img), FormatEWF)
	if err != nil {
		return // rejecting it at open time is fine too
	}
	defer r.Close()
	if _, err := r.ReadAt(make([]byte, 16), 0); err == nil {
		t.Fatal("want an error when a stored chunk is unusable")
	}
}

// ---------------------------------------------------------- multi-segment

// ewfBuildSegment assembles one segment file image: the 13-byte file header,
// an optional volume section, a "sectors" section holding this segment's
// chunks, its table and the terminator. Chunk offsets are absolute within
// this segment (table base 0), matching EWF1 sets.
func ewfBuildSegment(t *testing.T, sig string, claim int, term string, withVolume bool,
	sectors uint64, stored [][]byte, compressed []bool, big bool) []byte {
	t.Helper()
	const bps, spc = 512, 64
	n := len(stored)

	put32 := func(b []byte, v uint32) {
		if big {
			binary.BigEndian.PutUint32(b, v)
		} else {
			binary.LittleEndian.PutUint32(b, v)
		}
	}
	put64 := func(b []byte, v uint64) {
		if big {
			binary.BigEndian.PutUint64(b, v)
		} else {
			binary.LittleEndian.PutUint64(b, v)
		}
	}
	desc := func(typ string, next, size int64) []byte {
		d := make([]byte, ewfDescSize)
		copy(d, typ)
		put64(d[16:], uint64(next))
		put64(d[24:], uint64(size))
		return d
	}

	pos := int64(ewfHeaderSize)
	volPos, volSize := int64(0), int64(0)
	if withVolume {
		volPos = pos
		volSize = ewfDescSize + 1052 // EnCase-style volume payload
		pos += volSize
	}
	secPos := pos
	secSize := int64(ewfDescSize)
	for _, s := range stored {
		secSize += int64(len(s))
	}
	pos += secSize
	tblPos := pos
	tblSize := int64(ewfDescSize + ewfTableHdr + 4*n)
	pos += tblSize
	termPos := pos

	img := make([]byte, termPos+ewfDescSize)
	copy(img, sig)
	img[8] = 0x01
	binary.LittleEndian.PutUint16(img[9:], uint16(claim))

	if withVolume {
		copy(img[volPos:], desc("volume", secPos, volSize))
		vp := img[volPos+ewfDescSize:]
		vp[0] = 1
		put32(vp[4:], uint32(n))
		put32(vp[8:], spc)
		put32(vp[12:], bps)
		put64(vp[16:], sectors)
		vp[52] = 1 // compression level
	}

	copy(img[secPos:], desc("sectors", tblPos, secSize))
	off := secPos + ewfDescSize
	chunkOff := make([]int64, n)
	for i, s := range stored {
		chunkOff[i] = off
		copy(img[off:], s)
		off += int64(len(s))
	}

	copy(img[tblPos:], desc("table", termPos, tblSize))
	th := img[tblPos+ewfDescSize:]
	put32(th[0:], uint32(n))
	for i := 0; i < n; i++ {
		v := uint32(chunkOff[i])
		if compressed[i] {
			v |= ewfCompressMSB
		}
		put32(th[ewfTableHdr+i*4:], v)
	}

	copy(img[termPos:], desc(term, termPos, 0))
	return img
}

// buildE01Set writes a multi-segment E01 image (an L01 set when logical is
// set) and returns the segment paths in order. Chunks are distributed
// contiguously: segment k holds chunks [k*n/nSeg, (k+1)*n/nSeg). Only
// segment 1 carries the volume section; every segment but the last ends in a
// "next" terminator.
func buildE01Set(t *testing.T, data []byte, nSeg int, big bool, logical bool) []string {
	t.Helper()
	if nSeg < 1 {
		t.Fatalf("nSeg = %d", nSeg)
	}
	stored, compressed := ewfChunks(t, data)
	n := len(stored)
	if nSeg > n {
		t.Fatalf("%d segments for only %d chunks", nSeg, n)
	}
	sig, series := ewfSignature, "E"
	if logical {
		sig, series = ewfSignatureL01, "L"
	}
	sectors := uint64(len(data) / 512)

	dir := t.TempDir()
	paths := make([]string, nSeg)
	for k := 0; k < nSeg; k++ {
		lo, hi := k*n/nSeg, (k+1)*n/nSeg
		term := "next"
		if k == nSeg-1 {
			term = "done"
		}
		img := ewfBuildSegment(t, sig, k+1, term, k == 0, sectors,
			stored[lo:hi], compressed[lo:hi], big)
		p := filepath.Join(dir, fmt.Sprintf("image.%s%02d", series, k+1))
		if err := os.WriteFile(p, img, 0o600); err != nil {
			t.Fatal(err)
		}
		paths[k] = p
	}
	return paths
}

func TestEWFMultiSegment(t *testing.T) {
	data := ewfPayload(160) // 3 chunks of 32 KiB
	cs := int64(512 * 64)
	for _, big := range []bool{false, true} {
		for _, nSeg := range []int{2, 3} {
			name := fmt.Sprintf("seg%d/little-endian", nSeg)
			if big {
				name = fmt.Sprintf("seg%d/big-endian", nSeg)
			}
			t.Run(name, func(t *testing.T) {
				paths := buildE01Set(t, data, nSeg, big, false)
				r, err := Open(paths[0])
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				if r.Format() != FormatEWF {
					t.Fatalf("Format() = %q, want ewf", r.Format())
				}
				if r.Size() != int64(len(data)) {
					t.Fatalf("Size() = %d, want %d", r.Size(), len(data))
				}
				if got := readRange(t, r, 0, len(data)); !bytes.Equal(got, data) {
					t.Fatal("multi-segment payload mismatch")
				}
				for k := 1; k < nSeg; k++ {
					off := int64(k)*cs - 2
					if got := readRange(t, r, off, 8); !bytes.Equal(got, data[off:off+8]) {
						t.Fatalf("read across segment boundary at %d mismatch", off)
					}
				}
				checkBounds(t, r)
			})
		}
	}
}

func TestEWFMultiSegmentOpenAny(t *testing.T) {
	data := ewfPayload(160)
	paths := buildE01Set(t, data, 3, false, false)
	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			r, err := Open(p)
			if err != nil {
				t.Fatalf("Open(%s): %v", filepath.Base(p), err)
			}
			defer r.Close()
			if r.Format() != FormatEWF {
				t.Fatalf("Format() = %q, want ewf", r.Format())
			}
			if got := readRange(t, r, 0, len(data)); !bytes.Equal(got, data) {
				t.Fatal("payload mismatch")
			}
			checkBounds(t, r)
		})
	}
}

func TestEWFL01(t *testing.T) {
	data := ewfPayload(160)
	t.Run("single", func(t *testing.T) {
		paths := buildE01Set(t, data, 1, false, true)
		r, err := Open(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if r.Format() != FormatL01 {
			t.Fatalf("Format() = %q, want l01", r.Format())
		}
		if got := readRange(t, r, 0, len(data)); !bytes.Equal(got, data) {
			t.Fatal("L01 payload mismatch")
		}
		checkBounds(t, r)
	})
	t.Run("multi", func(t *testing.T) {
		paths := buildE01Set(t, data, 3, false, true)
		r, err := Open(paths[2]) // open the last segment
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if r.Format() != FormatL01 {
			t.Fatalf("Format() = %q, want l01", r.Format())
		}
		if got := readRange(t, r, 0, len(data)); !bytes.Equal(got, data) {
			t.Fatal("multi-segment L01 payload mismatch")
		}
		checkBounds(t, r)
	})
	t.Run("mvf-variant", func(t *testing.T) {
		paths := buildE01Set(t, data, 1, false, true)
		b, err := os.ReadFile(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		copy(b, ewfSignatureMV)
		if err := os.WriteFile(paths[0], b, 0o600); err != nil {
			t.Fatal(err)
		}
		r, err := Open(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if r.Format() != FormatL01 {
			t.Fatalf("Format() = %q, want l01", r.Format())
		}
		if got := readRange(t, r, 0, len(data)); !bytes.Equal(got, data) {
			t.Fatal("MVF-variant L01 payload mismatch")
		}
	})
}

func TestEWFSegmentSetErrors(t *testing.T) {
	data := ewfPayload(160)

	mutate := func(t *testing.T, p string, fn func([]byte)) {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		fn(b)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	wantErr := func(t *testing.T, err error, sub string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), sub) {
			t.Fatalf("err = %v, want error containing %q", err, sub)
		}
	}

	t.Run("missing-middle", func(t *testing.T) {
		paths := buildE01Set(t, data, 3, false, false)
		if err := os.Remove(paths[1]); err != nil {
			t.Fatal(err)
		}
		_, err := Open(paths[0])
		wantErr(t, err, "segment number mismatch")
	})
	t.Run("claim-mismatch", func(t *testing.T) {
		paths := buildE01Set(t, data, 3, false, false)
		mutate(t, paths[1], func(b []byte) {
			binary.LittleEndian.PutUint16(b[9:], 5)
		})
		_, err := Open(paths[0])
		wantErr(t, err, "segment number mismatch")
	})
	t.Run("mixed-signature", func(t *testing.T) {
		paths := buildE01Set(t, data, 2, false, false)
		mutate(t, paths[1], func(b []byte) {
			copy(b, ewfSignatureL01)
		})
		_, err := Open(paths[0])
		wantErr(t, err, "different signature")
	})
	t.Run("stray-complete-set", func(t *testing.T) {
		paths := buildE01Set(t, data, 1, false, false)
		stray := filepath.Join(filepath.Dir(paths[0]), "image.E02")
		if err := os.WriteFile(stray, make([]byte, 64), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Open(paths[0])
		wantErr(t, err, "marks the set complete")
	})
	t.Run("missing-continuation", func(t *testing.T) {
		paths := buildE01Set(t, data, 3, false, false)
		if err := os.Remove(paths[2]); err != nil {
			t.Fatal(err)
		}
		_, err := Open(paths[0])
		wantErr(t, err, "missing continuation")
	})
	t.Run("non-series-naming", func(t *testing.T) {
		img := make([]byte, 64)
		copy(img, ewfSignature)
		img[8] = 0x01
		binary.LittleEndian.PutUint16(img[9:], 5)
		_, err := Open(writeImg(t, "evidence.dd", img))
		wantErr(t, err, "not an E01/L01 segment naming")
	})
}
