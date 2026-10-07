package fs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// fatImg is a test-side writer for FAT images created by mkfs.fat. It
// only manipulates structures documented in the FAT specification; all
// geometry originates from dosfstools so the parser is checked against an
// independent formatter.
type fatImg struct {
	img        []byte
	bps        int
	spc        int
	rsvd       int
	fatSz      int
	nFATs      int
	rootEntCnt int
	fatStart   int64
	rootStart  int64
	rootBytes  int64
	dataStart  int64
	clusBytes  int64
	fat32      bool
	fatType    int // 12, 16, 32
	rootClus   uint32
}

func openFatImg(img []byte) *fatImg {
	w := &fatImg{img: img, fatType: 32}
	w.bps = int(le16(img, 11))
	w.spc = int(img[13])
	w.rsvd = int(le16(img, 14))
	w.nFATs = int(img[16])
	w.rootEntCnt = int(le16(img, 17))
	w.fatStart = int64(w.rsvd) * int64(w.bps)
	fatSz16 := int(le16(img, 22))
	w.clusBytes = int64(w.spc) * int64(w.bps)
	if fatSz16 != 0 {
		w.fatSz = fatSz16
		rootSecs := (int64(w.rootEntCnt)*32 + int64(w.bps) - 1) / int64(w.bps)
		w.rootStart = w.fatStart + int64(w.nFATs)*int64(w.fatSz)*int64(w.bps)
		w.rootBytes = rootSecs * int64(w.bps)
		w.dataStart = w.rootStart + w.rootBytes
	} else {
		w.fatSz = int(le32(img, 36))
		w.fat32 = true
		w.rootClus = le32(img, 44)
		w.dataStart = w.fatStart + int64(w.nFATs)*int64(w.fatSz)*int64(w.bps)
	}
	totSec := int64(le16(img, 19))
	if totSec == 0 {
		totSec = int64(le32(img, 32))
	}
	dataSecs := totSec - w.dataStart/int64(w.bps)
	cnt := dataSecs / int64(w.spc)
	switch {
	case cnt < 4085:
		w.fatType = 12
	case cnt < 65525:
		w.fatType = 16
	default:
		w.fatType = 32
	}
	return w
}

func (w *fatImg) clusterOff(c uint32) int64 {
	return w.dataStart + int64(c-2)*w.clusBytes
}

func (w *fatImg) fatEntry(c uint32) uint32 {
	off := w.fatStart
	switch w.fatType {
	case 32:
		return le32(w.img, int(off+int64(c)*4)) & 0x0FFFFFFF
	case 12:
		if c&1 == 1 {
			v := le16(w.img, int(off+int64(c)*3/2))
			return uint32(v) >> 4
		}
		return uint32(le16(w.img, int(off+int64(c)*3/2))) & 0x0FFF
	default: // 16
		return uint32(le16(w.img, int(off+int64(c)*2)))
	}
}

func (w *fatImg) setFat(c, val uint32) {
	for f := 0; f < w.nFATs; f++ {
		base := w.fatStart + int64(f)*int64(w.fatSz)*int64(w.bps)
		switch w.fatType {
		case 32:
			put := uint32(le32(w.img, int(base+int64(c)*4)))&0xF0000000 | val
			binaryPut32(w.img, base+int64(c)*4, put)
		case 12:
			off := base + int64(c)*3/2
			if c&1 == 1 {
				v := le16(w.img, int(off))&0x000F | uint16(val&0x0FFF)<<4
				binaryPut16(w.img, off, v)
			} else {
				v := le16(w.img, int(off))&0xF000 | uint16(val&0x0FFF)
				binaryPut16(w.img, off, v)
			}
		default: // 16
			binaryPut16(w.img, base+int64(c)*2, uint16(val))
		}
	}
}

func binaryPut32(img []byte, off int64, v uint32) {
	img[off] = byte(v)
	img[off+1] = byte(v >> 8)
	img[off+2] = byte(v >> 16)
	img[off+3] = byte(v >> 24)
}

func binaryPut16(img []byte, off int64, v uint16) {
	img[off] = byte(v)
	img[off+1] = byte(v >> 8)
}

// allocCluster finds a free cluster and marks it allocated (EOC).
func (w *fatImg) allocCluster() uint32 {
	for c := uint32(2); c < 0x10000; c++ {
		if w.fatEntry(c) == 0 {
			w.setFat(c, w.eocVal())
			return c
		}
	}
	panic("fatImg: no free clusters")
}

func (w *fatImg) eocVal() uint32 {
	switch w.fatType {
	case 32:
		return 0x0FFFFFFF
	case 12:
		return 0x0FFF
	default:
		return 0xFFFF
	}
}

// writeChain allocates a chain for data and writes it; returns first
// cluster (0 when data is empty).
func (w *fatImg) writeChain(data []byte) uint32 {
	if len(data) == 0 {
		return 0
	}
	n := (len(data) + int(w.clusBytes) - 1) / int(w.clusBytes)
	first := uint32(0)
	prev := uint32(0)
	for i := 0; i < n; i++ {
		c := w.allocCluster()
		if i == 0 {
			first = c
		} else {
			w.setFat(prev, c)
		}
		prev = c
		chunk := data[i*int(w.clusBytes):]
		if len(chunk) > int(w.clusBytes) {
			chunk = chunk[:w.clusBytes]
		}
		copy(w.img[w.clusterOff(c):], chunk)
	}
	return first
}

// rootRange returns the byte window of the root directory.
func (w *fatImg) rootRange() (int64, int64) {
	if w.fat32 {
		// Root chain: walk clusters until a zero-sized free... use first
		// cluster only (test roots are tiny).
		return w.clusterOff(w.rootClus), w.clusterOff(w.rootClus) + w.clusBytes
	}
	return w.rootStart, w.rootStart + w.rootBytes
}

// dirRange returns the byte window of a subdirectory cluster chain
// (first cluster only; tests keep dirs to one cluster).
func (w *fatImg) dirRange(clus uint32) (int64, int64) {
	return w.clusterOff(clus), w.clusterOff(clus) + w.clusBytes
}

// findFreeSlot scans a dir window for the first 0x00 entry start.
func (w *fatImg) findFreeSlot(start, end int64) int64 {
	for off := start; off+32 <= end; off += 32 {
		if w.img[off] == 0x00 {
			return off
		}
	}
	panic("fatImg: directory full")
}

// addEntry writes an LFN (optional) + short entry into a directory window.
func (w *fatImg) addEntry(start, end int64, short string, lfn string, attr byte, clus uint32, size int64, deleted bool) {
	need := 1
	if lfn != "" {
		need += (len([]rune(lfn)) + 12) / 13
	}
	slot := w.findFreeSlot(start, end)
	// Ensure the whole run fits.
	for i := 1; i < need; i++ {
		if slot+int64(i)*32+32 > end || w.img[slot+int64(i)*32] != 0x00 {
			// Not contiguous free space; scan further.
			slot = w.findFreeSlot(slot+32, end)
			i = -1
			continue
		}
	}
	pos := slot
	if lfn != "" {
		pos = w.writeLFN(pos, short, lfn)
	}
	w.writeShort(pos, short, attr, clus, size, deleted)
}

func (w *fatImg) writeLFN(pos int64, short, lfn string) int64 {
	chars := []rune(lfn)
	parts := (len(chars) + 12) / 13
	sum := lfnChecksum(short)
	for p := parts; p >= 1; p-- {
		e := w.img[pos : pos+32]
		for i := range e {
			e[i] = 0
		}
		seq := byte(p)
		if p == parts {
			seq |= 0x40
		}
		e[0] = seq
		e[11] = 0x0F
		e[13] = sum
		lo, hi := (p-1)*13, p*13
		if lo > len(chars) {
			lo = len(chars)
		}
		if hi > len(chars) {
			hi = len(chars)
		}
		chunk := chars[lo:hi]
		writeLFNChars(e[1:11], chunk[0:minInt(5, len(chunk))])
		if len(chunk) > 5 {
			writeLFNChars(e[14:26], chunk[5:minInt(11, len(chunk))])
		}
		if len(chunk) > 11 {
			writeLFNChars(e[28:32], chunk[11:minInt(13, len(chunk))])
		}
		// Pad the tail with 0xFFFF after the terminator.
		pos += 32
	}
	return pos
}

func writeLFNChars(dst []byte, chars []rune) {
	for i := range dst {
		dst[i] = 0
	}
	for i, c := range chars {
		if i*2+1 < len(dst) {
			dst[i*2] = byte(c)
			dst[i*2+1] = byte(c >> 8)
		}
	}
}

func lfnChecksum(short string) byte {
	// The on-disk short name is 11 bytes space-padded, uppercased.
	b := make([]byte, 11)
	for i := range b {
		b[i] = ' '
	}
	copy(b, short)
	var sum byte
	for _, c := range b {
		sum = ((sum & 1) << 7) + (sum >> 1) + c
	}
	return sum
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// fatDate = 2024-01-15, fatTime = 12:34:56.
const (
	fatDate = uint16((44 << 9) | (1 << 5) | 15)
	fatTime = uint16((12 << 11) | (34 << 5) | (56 / 2))
)

func (w *fatImg) writeShort(pos int64, short string, attr byte, clus uint32, size int64, deleted bool) {
	if len(short) != 11 {
		panic("fatImg: short name must be 11 bytes, got " + short)
	}
	e := w.img[pos : pos+32]
	for i := range e {
		e[i] = 0
	}
	var name [11]byte
	for i := range name {
		name[i] = ' '
	}
	copy(name[:], short) // caller passes the raw 11-byte form
	copy(e[0:11], name[:])
	e[11] = attr
	binaryPut16(e, 14, fatDate) // creation date
	binaryPut16(e, 16, fatDate) // creation time
	binaryPut16(e, 22, fatTime) // write time
	binaryPut16(e, 24, fatDate) // write date
	binaryPut16(e, 26, uint16(clus&0xFFFF))
	binaryPut16(e, 20, uint16(clus>>16))
	e[28] = byte(size)
	e[29] = byte(size >> 8)
	e[30] = byte(size >> 16)
	e[31] = byte(size >> 24)
	if deleted {
		e[0] = 0xE5
	}
}

// mkfat builds a FAT image of the given type and size via mkfs.fat.
func mkfat(t *testing.T, typ int, sizeMB int, label string) []byte {
	t.Helper()
	requireTool(t, "mkfs.fat")
	p := filepath.Join(t.TempDir(), "fat.img")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(sizeMB) << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	runCmd(t, "mkfs.fat", "-F", itoa(typ), "-n", label, p)
	img, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// splitShort splits an 11-byte raw short name into base+ext fields.
func shortFields(raw string) (string, string) {
	if len(raw) != 11 {
		panic("short name must be 11 bytes")
	}
	return raw[:8], raw[8:]
}

func TestFAT32ProbeLabel(t *testing.T) {
	img := mkfat(t, 32, 64, "GOHEXTEST")
	f := memFS(t, img)
	if f.Type() != "fat32" {
		t.Fatalf("type=%s", f.Type())
	}
	if f.Label() != "GOHEXTEST" {
		t.Fatalf("label=%q", f.Label())
	}
	if f.TotalSize() != int64(len(img)) {
		t.Fatalf("size=%d", f.TotalSize())
	}
}

func TestFAT32TreeAndRead(t *testing.T) {
	img := mkfat(t, 32, 64, "GOHEXTEST")
	w := openFatImg(img)

	// Root: plain 8.3 file.
	helloData := []byte("Hello FAT32!")
	hc := w.writeChain(helloData)
	rs, re := w.rootRange()
	w.addEntry(rs, re, "HELLO   TXT", "", 0x20, hc, int64(len(helloData)), false)

	// Root: long-name file (data spans multiple clusters).
	big := bytes.Repeat([]byte("0123456789abcdef"), 1024) // 16 KiB
	bc := w.writeChain(big)
	w.addEntry(rs, re, "QUARTER1XLS", "Quarterly Report 2024.xlsx", 0x20, bc, int64(len(big)), false)

	// Root: subdirectory with a nested file.
	docClus := w.allocCluster()
	w.addEntry(rs, re, "DOCS       ", "docs", 0x10, docClus, 0, false)
	ds, de := w.dirRange(docClus)
	// "." and ".."
	w.addEntry(ds, de, ".          ", "", 0x10, docClus, 0, false)
	w.addEntry(ds, de, "..         ", "", 0x10, 0, 0, false)
	notes := []byte("nested notes\n")
	nc := w.writeChain(notes)
	w.addEntry(ds, de, "NOTES   TXT", "notes.txt", 0x20, nc, int64(len(notes)), false)

	// Root: deleted file (short entry first byte cleared; LFN left intact
	// the way a real delete does).
	gone := []byte("deleted payload")
	gc := w.writeChain(gone)
	w.addEntry(rs, re, "GONE    TXT", "gone.txt", 0x20, gc, int64(len(gone)), true)

	// Root: empty file (no clusters).
	w.addEntry(rs, re, "EMPTY   TXT", "", 0x20, 0, 0, false)

	// Root: deleted file without an LFN — first character is lost per spec.
	old := []byte("old")
	oc := w.writeChain(old)
	w.addEntry(rs, re, "OLDDATA TXT", "", 0x20, oc, int64(len(old)), true)

	f := memFS(t, img)

	root, err := f.List("/")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"HELLO.TXT", "Quarterly Report 2024.xlsx", "docs", "gone.txt", "EMPTY.TXT", "?LDDATA.TXT"}
	got := names(root)
	for _, w := range want {
		if !contains(root, w) {
			t.Fatalf("root missing %q; got %v", w, got)
		}
	}
	if contains(root, "GOHEXTEST") {
		t.Fatalf("volume label leaked into listing: %v", got)
	}
	// "." ".." must not appear
	if contains(root, ".") || contains(root, "..") {
		t.Fatalf("dot entries leaked: %v", got)
	}

	if !findEntry(t, root, "gone.txt").Deleted {
		t.Fatal("gone.txt should be marked deleted")
	}
	if findEntry(t, root, "docs").Dir != true {
		t.Fatal("docs should be a dir")
	}

	// Content checks (case-insensitive path resolution too).
	if got := readAll(t, f, "/hello.txt"); !bytes.Equal(got, helloData) {
		t.Fatalf("hello content=%q", got)
	}
	if got := readAll(t, f, "/QUARTERLY REPORT 2024.XLSX"); !bytes.Equal(got, big) {
		t.Fatal("long-name content mismatch")
	}
	if got := readAll(t, f, "/docs/notes.txt"); !bytes.Equal(got, notes) {
		t.Fatalf("nested content=%q", got)
	}

	// Stat metadata.
	st, err := f.Stat("/HELLO.TXT")
	if err != nil {
		t.Fatal(err)
	}
	if st.Size != int64(len(helloData)) {
		t.Fatalf("size=%d", st.Size)
	}
	if st.Modified.Year() != 2024 || st.Modified.Month() != 1 || st.Modified.Day() != 15 {
		t.Fatalf("mtime=%v", st.Modified)
	}
	if st.Modified.Hour() != 12 || st.Modified.Minute() != 34 || st.Modified.Second() != 56 {
		t.Fatalf("mtime clock=%v", st.Modified)
	}

	// Nested listing excludes dots.
	docs, err := f.List("/docs")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(docs, "notes.txt") || contains(docs, ".") {
		t.Fatalf("docs=%v", names(docs))
	}

	// Error paths.
	if _, err := f.List("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("List missing: %v", err)
	}
	if _, err := f.List("/HELLO.TXT"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("List on file: %v", err)
	}
	if _, err := f.ReadAt("/docs", 0, make([]byte, 1)); !errors.Is(err, ErrIsDir) {
		t.Fatalf("ReadAt on dir: %v", err)
	}
	buf := make([]byte, 4)
	if n, err := f.ReadAt("/HELLO.TXT", int64(len(helloData))-2, buf); n != 2 || !errors.Is(err, io.EOF) {
		t.Fatalf("tail read n=%d err=%v", n, err)
	}
	if _, err := f.ReadAt("/EMPTY.TXT", 0, buf); !errors.Is(err, io.EOF) {
		t.Fatalf("empty read err=%v", err)
	}
	if _, err := f.Stat("/docs/none.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stat missing: %v", err)
	}
}

func TestFAT16ProbeAndRead(t *testing.T) {
	img := mkfat(t, 16, 16, "FAT16VOL")
	w := openFatImg(img)
	data := []byte("fat16 says hi")
	c := w.writeChain(data)
	rs, re := w.rootRange()
	w.addEntry(rs, re, "SAYHI   TXT", "", 0x20, c, int64(len(data)), false)

	f := memFS(t, img)
	if f.Type() != "fat16" {
		t.Fatalf("type=%s", f.Type())
	}
	if f.Label() != "FAT16VOL" {
		t.Fatalf("label=%q", f.Label())
	}
	if got := readAll(t, f, "/SAYHI.TXT"); !bytes.Equal(got, data) {
		t.Fatalf("content=%q", got)
	}
}

func TestFAT12Probe(t *testing.T) {
	img := mkfat(t, 12, 2, "FAT12VOL")
	f := memFS(t, img)
	if f.Type() != "fat12" {
		t.Fatalf("type=%s", f.Type())
	}
	if f.Label() != "FAT12VOL" {
		t.Fatalf("label=%q", f.Label())
	}
	root, err := f.List("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(root) != 0 {
		t.Fatalf("expected empty root, got %v", names(root))
	}
}

func TestFATNotFATRejected(t *testing.T) {
	img := make([]byte, 16*1024)
	img[510], img[511] = 0x55, 0xAA
	if _, err := Probe(memReader{img}, 0, int64(len(img))); err == nil {
		t.Fatal("expected probe failure for random boot sector")
	}
}
