package fs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// exfatImg is a test-side writer for exFAT images created by mkfs.exfat.
type exfatImg struct {
	img      []byte
	clus     int64
	heapOff  int64
	fatOff   int64
	rootClus uint32
}

func openExfatImg(t *testing.T, img []byte) *exfatImg {
	t.Helper()
	// exFAT: BytesPerSectorShift @108, SectorsPerClusterShift @109.
	clusShift := int(img[108]) + int(img[109])
	if clusShift < 9 || clusShift > 25 {
		t.Fatalf("bad cluster shift %d", clusShift)
	}
	fatSecs := int64(le32(img, 80))
	heapSecs := int64(le32(img, 88))
	w := &exfatImg{
		img:      img,
		clus:     int64(1) << clusShift,
		fatOff:   fatSecs * 512,
		heapOff:  heapSecs * 512,
		rootClus: le32(img, 96),
	}
	return w
}

func (w *exfatImg) clusterOff(c uint32) int64 {
	return w.heapOff + int64(c-2)*w.clus
}

func (w *exfatImg) fatSet(c, v uint32) {
	off := w.fatOff + int64(c)*4
	binaryPut32(w.img, off, v)
}

func (w *exfatImg) fatGet(c uint32) uint32 {
	return le32(w.img, int(w.fatOff+int64(c)*4))
}

// allocCluster marks a fresh cluster allocated (EOC).
func (w *exfatImg) allocCluster() uint32 {
	for c := uint32(2); c < 0x10000000; c++ {
		if w.fatGet(c) == 0 {
			w.fatSet(c, 0xFFFFFFFF)
			return c
		}
	}
	panic("exfatImg: no free clusters")
}

// allocRun finds n contiguous free clusters, chains them (for realism)
// and returns the first cluster.
func (w *exfatImg) allocRun(n int) uint32 {
	var run []uint32
	flush := func() {
		if len(run) == n {
			for i, c := range run {
				if i == n-1 {
					w.fatSet(c, 0xFFFFFFFF)
				} else {
					w.fatSet(c, run[i+1])
				}
			}
		}
		run = nil
	}
	for c := uint32(2); c < 0x10000000; c++ {
		if w.fatGet(c) == 0 {
			run = append(run, c)
			if len(run) == n {
				first := run[0]
				flush()
				return first
			}
		} else {
			run = nil
		}
	}
	panic("exfatImg: no contiguous run")
}

// rootBytes returns the raw root directory bytes (FAT chain walk).
func (w *exfatImg) rootBytes() []byte {
	var out []byte
	c := w.rootClus
	seen := map[uint32]bool{}
	for c >= 2 && c < 0xFFFFFFF8 && !seen[c] {
		seen[c] = true
		off := w.clusterOff(c)
		out = append(out, w.img[off:off+w.clus]...)
		next := w.fatGet(c)
		if next == 0 || next >= 0xFFFFFFF8 {
			break
		}
		c = next
	}
	return out
}

// writeRootRaw overwrites the root directory contents.
func (w *exfatImg) writeRootRaw(data []byte) {
	if int64(len(data)) > w.clus {
		panic("exfatImg: root dir too big for single-cluster test")
	}
	off := w.clusterOff(w.rootClus)
	copy(w.img[off:], data)
}

// put appends a FILE/STREAM/NAME group (or a LABEL entry) to the root
// directory, writing into the first zeroed slot.
func (w *exfatImg) put(entries ...[]byte) {
	root := w.rootBytes()
	slot := -1
	for i := 0; i+32 <= len(root); i += 32 {
		if root[i] == 0 {
			slot = i
			break
		}
	}
	if slot < 0 {
		panic("exfatImg: root directory full")
	}
	need := len(entries) * 32
	if slot+need > len(root) {
		panic("exfatImg: not enough root slots")
	}
	for i, e := range entries {
		copy(root[slot+i*32:], e)
	}
	w.writeRootRaw(root)
}

// fileGroup builds FILE + STREAM + NAME entries.
func fileGroup(name string, attr uint16, clus uint32, size, valid int64, noChain bool, deleted bool) [][]byte {
	file := make([]byte, 32)
	file[0] = exEntryFile
	if deleted {
		file[0] = exEntryFile & 0x7F
	}
	file[1] = 0 // SecondaryCount filled after name parts are known
	binaryPut16(file, 4, attr)
	// Timestamps: 2024-01-15 12:34:56.
	ts := uint16((12 << 11) | (34 << 5) | (56 / 2))
	td := uint16(((2024 - 1980) << 9) | (1 << 5) | 15)
	binaryPut16(file, 8, ts)
	binaryPut16(file, 10, td)
	binaryPut16(file, 12, ts)
	binaryPut16(file, 14, td)
	binaryPut16(file, 16, ts)
	binaryPut16(file, 18, td)

	stream := make([]byte, 32)
	stream[0] = exEntryStream
	if noChain {
		stream[1] = 0x02 // ALLOCATE_NO_FAT_CHAIN
	}
	binaryPut64 := func(b []byte, off int, v uint64) {
		for i := 0; i < 8; i++ {
			b[off+i] = byte(v >> (8 * i))
		}
	}
	binaryPut64(stream, 8, uint64(valid))
	binaryPut32(stream, 20, clus)
	binaryPut64(stream, 24, uint64(size))

	var parts [][]byte
	for i := 0; i < len(name); i += 15 {
		end := i + 15
		if end > len(name) {
			end = len(name)
		}
		chunk := []rune(name[i:end])
		nm := make([]byte, 32)
		nm[0] = exEntryName
		for j, c := range chunk {
			nm[2+j*2] = byte(c)
			nm[3+j*2] = byte(c >> 8)
		}
		parts = append(parts, nm)
	}
	// SecondaryCount lives at byte 1 of the FILE entry.
	file[1] = byte(len(parts))
	out := [][]byte{file, stream}
	out = append(out, parts...)
	return out
}

// labelEntry builds a volume label entry (0x83).
func labelEntry(label string) []byte {
	e := make([]byte, 32)
	e[0] = exEntryLabel
	binaryPut16(e, 1, uint16(len([]rune(label))))
	for i, c := range []rune(label) {
		if i >= 11 {
			break
		}
		e[2+i*2] = byte(c)
		e[3+i*2] = byte(c >> 8)
	}
	return e
}

// mkexfat builds an exFAT image via mkfs.exfat.
func mkexfat(t *testing.T, sizeMB int, label string) []byte {
	t.Helper()
	requireTool(t, "mkfs.exfat")
	p := filepath.Join(t.TempDir(), "exfat.img")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(sizeMB) << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	args := []string{"-L", label}
	if label == "" {
		args = nil
	}
	args = append(args, p)
	runCmd(t, "mkfs.exfat", args...)
	img, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func TestExFATProbeLabel(t *testing.T) {
	img := mkexfat(t, 32, "GHEXEXFAT")
	f := memFS(t, img)
	if f.Type() != "exfat" {
		t.Fatalf("type=%s", f.Type())
	}
	if f.Label() != "GHEXEXFAT" {
		t.Fatalf("label=%q", f.Label())
	}
	if f.TotalSize() != int64(len(img)) {
		t.Fatalf("total=%d", f.TotalSize())
	}
}

func TestExFATTreeAndRead(t *testing.T) {
	img := mkexfat(t, 32, "GHEXEXFAT")
	w := openExfatImg(t, img)

	// File with FAT chain (noChain=false): two clusters.
	hello := []byte("Hello exFAT world!")
	c1 := w.allocCluster()
	w.fatSet(c1, w.allocCluster())
	copy(w.img[w.clusterOff(c1):], hello)

	// Contiguous file (noChain=true): reserve a physically contiguous run
	// so later cluster allocations cannot overwrite its bytes.
	big := bytes.Repeat([]byte("exfat-contig-0123456789"), 500) // 11500 B
	nBig := (len(big) + int(w.clus) - 1) / int(w.clus)
	bc := w.allocRun(nBig)
	copy(w.img[w.clusterOff(bc):], big)

	// Directory with a nested file.
	dcl := w.allocCluster()
	w.put(fileGroup("docs", 0x10, dcl, 0, 0, true, false)...)
	nested := []byte("nested exFAT note\n")
	nc := w.allocCluster()
	copy(w.img[w.clusterOff(nc):], nested)
	// Write entries into the directory cluster directly.
	var dblob []byte
	for _, e := range fileGroup("notes.txt", 0x20, nc, int64(len(nested)), int64(len(nested)), true, false) {
		dblob = append(dblob, e...)
	}
	copy(w.img[w.clusterOff(dcl):], dblob)

	// Root files.
	w.put(fileGroup("hello.txt", 0x20, c1, int64(len(hello)), int64(len(hello)), false, false)...)
	w.put(fileGroup("big.bin", 0x20, bc, int64(len(big)), int64(len(big)), true, false)...)

	// Deleted file (IN_USE cleared on FILE).
	w.put(fileGroup("gone.txt", 0x20, w.allocCluster(), 5, 5, true, true)...)

	f := memFS(t, img)

	root, err := f.List("/")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"hello.txt", "big.bin", "docs"} {
		if !contains(root, n) {
			t.Fatalf("root missing %q: %v", n, names(root))
		}
	}
	if findEntry(t, root, "docs").Dir != true {
		t.Fatal("docs should be a dir")
	}

	if got := readAll(t, f, "/hello.txt"); !bytes.Equal(got, hello) {
		t.Fatalf("hello=%q", got)
	}
	if got := readAll(t, f, "/big.bin"); !bytes.Equal(got, big) {
		t.Fatalf("big mismatch: %d vs %d", len(got), len(big))
	}
	// Case-insensitive.
	if got := readAll(t, f, "/HELLO.TXT"); !bytes.Equal(got, hello) {
		t.Fatal("case-insensitive read failed")
	}

	// Nested.
	docs, err := f.List("/docs")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(docs, "notes.txt") {
		t.Fatalf("docs: %v", names(docs))
	}
	if got := readAll(t, f, "/docs/notes.txt"); !bytes.Equal(got, nested) {
		t.Fatalf("nested=%q", got)
	}

	// Stat timestamps come from the modified field.
	st, err := f.Stat("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if st.Size != int64(len(hello)) {
		t.Fatalf("size=%d", st.Size)
	}
	if st.Modified.Year() != 2024 || st.Modified.Month() != time.January || st.Modified.Day() != 15 {
		t.Fatalf("mtime=%v", st.Modified)
	}

	// Errors.
	if _, err := f.List("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("list missing: %v", err)
	}
	if _, err := f.List("/hello.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("list file: %v", err)
	}
	if _, err := f.ReadAt("/docs", 0, make([]byte, 1)); !errors.Is(err, ErrIsDir) {
		t.Fatalf("read dir: %v", err)
	}
	if n, err := f.ReadAt("/hello.txt", int64(len(hello)), make([]byte, 4)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("eof: n=%d err=%v", n, err)
	}
}

func TestExFATLabelEntry(t *testing.T) {
	// mkfs.exfat without -L: no label entry; we add one ourselves.
	img := mkexfat(t, 32, "")
	w := openExfatImg(t, img)
	f := memFS(t, img)
	if f.Label() != "" {
		t.Fatalf("expected empty label, got %q", f.Label())
	}
	w.put(labelEntry("MYVOL"))
	f = memFS(t, img)
	if f.Label() != "MYVOL" {
		t.Fatalf("label=%q", f.Label())
	}
}

func TestExFATRejectsGarbage(t *testing.T) {
	img := make([]byte, 16*1024)
	img[510], img[511] = 0x55, 0xAA
	if _, err := Probe(memReader{img}, 0, int64(len(img))); err == nil {
		t.Fatal("expected probe failure")
	}
}
