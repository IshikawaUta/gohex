package fs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// --- HFS+ image builder ----------------------------------------------------
//
// No mkfs.hfsplus exists on CI, so the fixture is assembled from the exact
// structures in Apple TN1150 / linux hfsplus_raw.h. Layout (4096-byte
// blocks, 32 blocks total):
//
//	0        volume header (bytes 1024..1536)
//	4..5     catalog B-tree (header node, leaf node)
//	6..7     extents-overflow B-tree (header node, leaf node)
//	8        allocation bitmap
//	9..16    big.dat data blocks 0..7 (8 inline extents)
//	17       big.dat data block 8 (overflow extent)
//	18       hello.txt
//	19       readme.md
//	20       sparse.dat block 0

const (
	hfsTestBlock    = 4096
	hfsTestBlocks   = 32
	hfsTestDate     = 3786912000 // 2024-01-01T00:00:00Z in HFS+ seconds
	hfsTestHello    = "Hello, HFS+ world!\n"
	hfsTestReadme   = "readme\n"
	hfsTestBigSize  = 9 * hfsTestBlock
	hfsTestSparseSz = 5000
)

func putBE16(b []byte, off int, v uint16) { binary.BigEndian.PutUint16(b[off:], v) }
func putBE32(b []byte, off int, v uint32) { binary.BigEndian.PutUint32(b[off:], v) }
func putBE64(b []byte, off int, v uint64) { binary.BigEndian.PutUint64(b[off:], v) }

type hfsRec struct {
	key  []byte // key content (without the keyLength field)
	data []byte
}

// hfsBuildNode serializes one B-tree node with an offset table at the end.
func hfsBuildNode(nodeSize int, typ, height byte, next, prev uint32, recs []hfsRec) []byte {
	node := make([]byte, nodeSize)
	putBE32(node, 0, next)
	putBE32(node, 4, prev)
	node[8] = typ
	node[9] = height
	putBE16(node, 10, uint16(len(recs)))
	off := 14
	offs := make([]uint16, 0, len(recs))
	for _, r := range recs {
		offs = append(offs, uint16(off))
		putBE16(node, off, uint16(len(r.key)))
		copy(node[off+2:], r.key)
		p := off + 2 + len(r.key)
		if p%2 != 0 {
			p++
		}
		copy(node[p:], r.data)
		off = p + len(r.data)
	}
	free := off
	if limit := nodeSize - 2*(len(recs)+1); free > limit {
		panic("hfs fixture: node overflow")
	}
	for i, o := range offs {
		putBE16(node, nodeSize-2*(i+1), o)
	}
	putBE16(node, nodeSize-2*(len(recs)+1), uint16(free))
	return node
}

// hfsHeaderNode builds node 0 (header record + user bytes + node bitmap).
func hfsHeaderNode(nodeSize int, hdr []byte, usedNodes int) []byte {
	node := make([]byte, nodeSize)
	node[8] = hfsNodeHeader
	putBE16(node, 10, 3)
	copy(node[14:], hdr)
	// Node bitmap starts at 248 (14 + 106 + 128).
	for i := 0; i < usedNodes; i++ {
		node[248+i/8] |= 0x80 >> (i % 8)
	}
	free := nodeSize - 8
	putBE16(node, nodeSize-2, 14)
	putBE16(node, nodeSize-4, 14+106)
	putBE16(node, nodeSize-6, 248)
	putBE16(node, nodeSize-8, uint16(free))
	return node
}

// hfsHeaderRec builds the 106-byte B-tree header record.
func hfsHeaderRec(depth uint16, root, leafCount, leafHead, leafTail, nodeCount, freeNodes uint32,
	nodeSize, maxKeyLen uint16, keyType byte,
) []byte {
	h := make([]byte, 106)
	putBE16(h, 0, depth)
	putBE32(h, 2, root)
	putBE32(h, 6, leafCount)
	putBE32(h, 10, leafHead)
	putBE32(h, 14, leafTail)
	putBE16(h, 18, nodeSize)
	putBE16(h, 20, maxKeyLen)
	putBE32(h, 22, nodeCount)
	putBE32(h, 26, freeNodes)
	putBE32(h, 32, 4096) // clump size
	h[37] = keyType
	putBE32(h, 38, hfsTreeBigKeys|hfsTreeVarIdxKeys)
	return h
}

func hfsUTF16BE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	put := func(u uint16) {
		out = append(out, byte(u>>8), byte(u))
	}
	for _, r := range s {
		if r > 0xFFFF {
			r -= 0x10000
			put(uint16(0xD800 + (r >> 10)))
			put(uint16(0xDC00 + (r & 0x3FF)))
			continue
		}
		put(uint16(r))
	}
	return out
}

func hfsCatKey(parent uint32, name string) []byte {
	k := make([]byte, 6, 6+len(name)*2)
	putBE32(k, 0, parent)
	putBE16(k, 4, uint16(len(name)))
	return append(k, hfsUTF16BE(name)...)
}

func hfsThreadKey(cnid uint32) []byte {
	k := make([]byte, 6)
	putBE32(k, 0, cnid)
	putBE16(k, 4, 0) // empty name
	return k
}

func hfsThreadData(parent uint32, typ uint16, name string) []byte {
	d := make([]byte, 10, 10+len(name)*2)
	putBE16(d, 0, typ)
	putBE32(d, 4, parent)
	putBE16(d, 8, uint16(len(name)))
	return append(d, hfsUTF16BE(name)...)
}

func hfsPerms(mode uint16) []byte {
	p := make([]byte, 16)
	putBE16(p, 10, mode)
	return p
}

func hfsFolderData(cnid, valence uint32, mode uint16) []byte {
	d := make([]byte, 88)
	putBE16(d, 0, hfsRecFolder)
	putBE16(d, 2, 0x0002) // thread exists
	putBE32(d, 4, valence)
	putBE32(d, 8, cnid)
	for _, off := range []int{12, 16, 20, 24, 28} {
		putBE32(d, off, hfsTestDate)
	}
	copy(d[32:], hfsPerms(mode))
	return d
}

type hfsExt struct{ start, count uint32 }

func hfsPutFork(d []byte, off int, size uint64, totalBlocks uint32, exts []hfsExt) {
	putBE64(d, off, size)
	putBE32(d, off+8, hfsTestBlock) // clump size
	putBE32(d, off+12, totalBlocks)
	for i, e := range exts {
		if i == 8 {
			break
		}
		putBE32(d, off+16+i*8, e.start)
		putBE32(d, off+20+i*8, e.count)
	}
}

func hfsFileData(cnid uint32, mode, flags uint16, fdType uint32, size uint64, exts []hfsExt) []byte {
	d := make([]byte, 248)
	putBE16(d, 0, hfsRecFile)
	putBE16(d, 2, flags)
	putBE32(d, 8, cnid)
	for _, off := range []int{12, 16, 20, 24, 28} {
		putBE32(d, off, hfsTestDate)
	}
	copy(d[32:], hfsPerms(mode))
	putBE32(d, 48, fdType)
	blocks := uint32(0)
	for _, e := range exts {
		blocks += e.count
	}
	hfsPutFork(d, 88, size, blocks, exts)
	return d
}

// hfsExtKey builds an extents-overflow key (keyLength = 10).
func hfsExtKey(forkType byte, cnid, startBlock uint32) []byte {
	k := make([]byte, 10)
	k[0] = forkType
	putBE32(k, 2, cnid)
	putBE32(k, 6, startBlock)
	return k
}

func buildHFSPlusImage() []byte {
	img := make([]byte, hfsTestBlocks*hfsTestBlock)

	// --- allocation bitmap (block 8) ---
	for i := 0; i <= 20; i++ {
		img[8*hfsTestBlock+i/8] |= 0x80 >> (i % 8)
	}

	// --- catalog B-tree (blocks 4..5) ---
	files := []hfsRec{
		{hfsCatKey(2, "GOHEX"), hfsFolderData(2, 4, 0o40755)},
		{hfsCatKey(2, "docs"), hfsFolderData(16, 1, 0o40755)},
		{hfsCatKey(2, "hello.txt"), hfsFileData(17, 0o100644, 0x0002, 0,
			uint64(len(hfsTestHello)), []hfsExt{{18, 1}})},
		{hfsCatKey(16, "readme.md"), hfsFileData(18, 0o100644, 0x0082, 0,
			uint64(len(hfsTestReadme)), []hfsExt{{19, 1}})},
		{hfsCatKey(2, "big.dat"), hfsFileData(19, 0o100644, 0x0002, hfsTypeHardlink,
			hfsTestBigSize, []hfsExt{{9, 1}, {10, 1}, {11, 1}, {12, 1}, {13, 1}, {14, 1}, {15, 1}, {16, 1}})},
		{hfsCatKey(2, "sparse.dat"), hfsFileData(20, 0o444, 0x0002, hfsTypeSymlink,
			hfsTestSparseSz, []hfsExt{{20, 1}})},
	}
	threads := []hfsRec{
		{hfsThreadKey(2), hfsThreadData(1, hfsRecFolderThread, "GOHEX")},
		{hfsThreadKey(16), hfsThreadData(2, hfsRecFolderThread, "docs")},
		{hfsThreadKey(17), hfsThreadData(2, hfsRecFileThread, "hello.txt")},
		{hfsThreadKey(18), hfsThreadData(16, hfsRecFileThread, "readme.md")},
		{hfsThreadKey(19), hfsThreadData(2, hfsRecFileThread, "big.dat")},
		{hfsThreadKey(20), hfsThreadData(2, hfsRecFileThread, "sparse.dat")},
	}
	leaf := hfsBuildNode(hfsTestBlock, hfsNodeLeaf, 1, 0, 0, append(threads, files...))
	copy(img[5*hfsTestBlock:], leaf)
	catHdr := hfsHeaderRec(1, 1, uint32(len(threads)+len(files)), 1, 1, 2, 0,
		hfsTestBlock, 516, hfsKeyCaseFold)
	copy(img[4*hfsTestBlock:], hfsHeaderNode(hfsTestBlock, catHdr, 2))

	// --- extents-overflow B-tree (blocks 6..7): one overflow extent ---
	ovfl := hfsBuildNode(hfsTestBlock, hfsNodeLeaf, 1, 0, 0, []hfsRec{
		{hfsExtKey(0, 19, 8), extRec([]hfsExt{{17, 1}})},
	})
	copy(img[7*hfsTestBlock:], ovfl)
	extHdr := hfsHeaderRec(1, 1, 1, 1, 1, 2, 0, hfsTestBlock, 10, hfsKeyCaseFold)
	copy(img[6*hfsTestBlock:], hfsHeaderNode(hfsTestBlock, extHdr, 2))

	// --- file data ---
	big := make([]byte, hfsTestBigSize)
	for i := range big {
		big[i] = byte(i / hfsTestBlock) // file block index per byte
	}
	for i := 0; i < 8; i++ {
		copy(img[(9+i)*hfsTestBlock:], big[i*hfsTestBlock:(i+1)*hfsTestBlock])
	}
	copy(img[17*hfsTestBlock:], big[8*hfsTestBlock:])
	copy(img[18*hfsTestBlock:], hfsTestHello)
	copy(img[19*hfsTestBlock:], hfsTestReadme)
	for i := 0; i < hfsTestBlock; i++ {
		img[20*hfsTestBlock+i] = 0xAB
	}

	// --- volume header at 1024 ---
	vh := img[1024:1536]
	putBE16(vh, 0, hfsSigPlus)
	putBE16(vh, 2, 4)    // version
	putBE32(vh, 4, 1<<8) // attributes: unmounted cleanly
	for _, off := range []int{16, 20, 24, 28} {
		putBE32(vh, off, hfsTestDate)
	}
	putBE32(vh, 32, 4)                                       // file count
	putBE32(vh, 36, 1)                                       // folder count (excludes root)
	putBE32(vh, 40, hfsTestBlock)                            // block size
	putBE32(vh, 44, hfsTestBlocks)                           // total blocks
	putBE32(vh, 48, hfsTestBlocks-21)                        // free blocks
	putBE32(vh, 64, 21)                                      // next CNID
	hfsPutFork(vh, 112, hfsTestBlock, 1, []hfsExt{{8, 1}})   // allocation file
	hfsPutFork(vh, 192, 2*hfsTestBlock, 2, []hfsExt{{6, 2}}) // extents file
	hfsPutFork(vh, 272, 2*hfsTestBlock, 2, []hfsExt{{4, 2}}) // catalog file
	return img
}

// extRec builds a 64-byte extents record (8 extent slots).
func extRec(exts []hfsExt) []byte {
	d := make([]byte, 64)
	for i, e := range exts {
		putBE32(d, i*8, e.start)
		putBE32(d, i*8+4, e.count)
	}
	return d
}

// --- tests -----------------------------------------------------------------

func TestHFSPlusBasic(t *testing.T) {
	f := memFS(t, buildHFSPlusImage())
	if f.Type() != "hfs+" {
		t.Fatalf("type=%s", f.Type())
	}
	if f.Label() != "GOHEX" {
		t.Fatalf("label=%q", f.Label())
	}
	if f.TotalSize() != hfsTestBlocks*hfsTestBlock {
		t.Fatalf("total=%d", f.TotalSize())
	}

	ents, err := f.List("/")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"docs", "hello.txt", "big.dat", "sparse.dat"} {
		if !contains(ents, name) {
			t.Fatalf("missing %q in %v", name, names(ents))
		}
	}
	docs := findEntry(t, ents, "docs")
	if !docs.Dir || docs.Size != 0 {
		t.Fatalf("docs=%+v", docs)
	}
	hello := findEntry(t, ents, "hello.txt")
	if hello.Dir || hello.Size != int64(len(hfsTestHello)) {
		t.Fatalf("hello=%+v", hello)
	}
	if big := findEntry(t, ents, "big.dat"); big.Size != hfsTestBigSize {
		t.Fatalf("big=%+v", big)
	}
	if sp := findEntry(t, ents, "sparse.dat"); sp.Size != hfsTestSparseSz {
		t.Fatalf("sparse=%+v", sp)
	}
	if hello.Modified.Year() != 2024 {
		t.Fatalf("modified=%v", hello.Modified)
	}
	if hello.Created.Year() != 2024 {
		t.Fatalf("created=%v", hello.Created)
	}

	sub, err := f.List("/docs")
	if err != nil {
		t.Fatal(err)
	}
	if len(sub) != 1 || sub[0].Name != "readme.md" || sub[0].Path != "/docs/readme.md" {
		t.Fatalf("docs entries: %+v", sub)
	}
}

func TestHFSPlusReads(t *testing.T) {
	f := memFS(t, buildHFSPlusImage())

	if got := readAll(t, f, "/hello.txt"); string(got) != hfsTestHello {
		t.Fatalf("hello=%q", got)
	}
	if got := readAll(t, f, "/docs/readme.md"); string(got) != hfsTestReadme {
		t.Fatalf("readme=%q", got)
	}

	// big.dat spans 8 inline extents plus one overflow extent; every byte
	// carries its file-block index.
	big := readAll(t, f, "/big.dat")
	if len(big) != hfsTestBigSize {
		t.Fatalf("len=%d", len(big))
	}
	for i, b := range big {
		if b != byte(i/hfsTestBlock) {
			t.Fatalf("byte %d = %d, want %d", i, b, i/hfsTestBlock)
		}
	}

	// sparse.dat: allocated block, then a hole to the logical size.
	sp := readAll(t, f, "/sparse.dat")
	if len(sp) != hfsTestSparseSz {
		t.Fatalf("sparse len=%d", len(sp))
	}
	if !bytes.Equal(sp[:hfsTestBlock], bytes.Repeat([]byte{0xAB}, hfsTestBlock)) {
		t.Fatal("sparse first block mismatch")
	}
	for i := hfsTestBlock; i < len(sp); i++ {
		if sp[i] != 0 {
			t.Fatalf("hole byte %d = %#x", i, sp[i])
		}
	}

	// Partial read at EOF returns a short buffer plus io.EOF.
	p := make([]byte, 8)
	n, err := f.ReadAt("/hello.txt", int64(len(hfsTestHello))-3, p)
	if n != 3 || err == nil || string(p[:n]) != "d!\n" {
		t.Fatalf("tail read n=%d err=%v p=%q", n, err, p[:n])
	}
}

func TestHFSPlusLookupAndAttrs(t *testing.T) {
	f := memFS(t, buildHFSPlusImage())

	// Key type 0xCF: case-insensitive lookups.
	st, err := f.Stat("/DOCS/README.MD")
	if err != nil {
		t.Fatalf("case-insensitive stat: %v", err)
	}
	if st.Name != "readme.md" {
		t.Fatalf("name=%q", st.Name)
	}
	if _, err := f.Stat("/HELLO.TXT"); err != nil {
		t.Fatalf("upper stat: %v", err)
	}

	ents, _ := f.List("/")
	if e := findEntry(t, ents, "big.dat"); len(e.Attributes) != 1 || e.Attributes[0] != "hardlink" {
		t.Fatalf("big.dat attrs=%v", e.Attributes)
	}
	if e := findEntry(t, ents, "sparse.dat"); len(e.Attributes) != 2 ||
		e.Attributes[0] != "readonly" || e.Attributes[1] != "symlink" {
		t.Fatalf("sparse attrs=%v", e.Attributes)
	}
	if e := findEntry(t, ents, "hello.txt"); len(e.Attributes) != 0 {
		t.Fatalf("hello attrs=%v", e.Attributes)
	}
	sub, _ := f.List("/docs")
	if e := findEntry(t, sub, "readme.md"); len(e.Attributes) != 1 || e.Attributes[0] != "compressed" {
		t.Fatalf("readme attrs=%v", e.Attributes)
	}
}

func TestHFSPlusErrors(t *testing.T) {
	img := buildHFSPlusImage()
	f := memFS(t, img)

	if _, err := f.List("/hello.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("List on file: %v", err)
	}
	if _, err := f.ReadAt("/docs", 0, make([]byte, 1)); !errors.Is(err, ErrIsDir) {
		t.Fatalf("ReadAt on dir: %v", err)
	}
	if _, err := f.Stat("/nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat missing: %v", err)
	}
	if _, err := f.Stat("/docs/nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Stat nested missing: %v", err)
	}
	if _, err := f.List("/hello.txt/x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("resolve below file: %v", err)
	}
}

// probeHFSPlus applies fn to a fresh image and returns the Probe error.
func probeHFSPlus(t *testing.T, fn func(img []byte)) error {
	t.Helper()
	img := buildHFSPlusImage()
	fn(img)
	_, err := Probe(memReader{img}, 0, int64(len(img)))
	return err
}

// corruptHFSPlus returns a view of a mutated image that still opens.
func corruptHFSPlus(t *testing.T, fn func(img []byte)) FS {
	t.Helper()
	img := buildHFSPlusImage()
	fn(img)
	f, err := Probe(memReader{img}, 0, int64(len(img)))
	if err != nil {
		t.Fatalf("Probe on mutated image: %v", err)
	}
	return f
}

func TestHFSPlusCorruptTrees(t *testing.T) {
	cases := []struct {
		name  string
		setup func([]byte)
		want  string
	}{
		{"catalog header missing", func(b []byte) { b[4*hfsTestBlock+8] = 0 }, "header node missing"},
		{"extents header missing", func(b []byte) { b[6*hfsTestBlock+8] = 0 }, "header node missing"},
		{"leaf cycle", func(b []byte) {
			binary.BigEndian.PutUint32(b[5*hfsTestBlock:], 1)
		}, "cycle"},
		{"non-leaf catalog node", func(b []byte) { b[5*hfsTestBlock+8] = 0x00 }, "not a leaf"},
		{"node out of range", func(b []byte) {
			binary.BigEndian.PutUint32(b[4*hfsTestBlock+24:], 100)
		}, "out of range"},
		{"truncated offset table", func(b []byte) {
			binary.BigEndian.PutUint16(b[5*hfsTestBlock+10:], 0xFFFF)
		}, "offset table"},
		{"bad record offsets", func(b []byte) {
			binary.BigEndian.PutUint16(b[7*hfsTestBlock+4096-2:], 2)
		}, "bad record offsets"},
		{"bad extents record", func(b []byte) {
			binary.BigEndian.PutUint16(b[7*hfsTestBlock+14:], 4)
		}, "bad extents record"},
		{"truncated folder record", func(b []byte) {
			// Record 6 is the root folder record: cut its data short.
			node := b[5*hfsTestBlock:]
			start := int(binary.BigEndian.Uint16(node[4096-2*(6+1):]))
			binary.BigEndian.PutUint16(node[4096-2*(6+2):], uint16(start+50))
		}, "truncated folder record"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := probeHFSPlus(t, tc.setup)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}

	t.Run("no extents overflow file", func(t *testing.T) {
		// Zero the extents fork: the volume still opens (big.dat loses its
		// overflow extent, so reads get zeros for that block).
		f := corruptHFSPlus(t, func(img []byte) {
			for i := 192; i < 272; i++ {
				img[1024+i] = 0
			}
		})
		if _, err := f.List("/"); err != nil {
			t.Fatalf("List: %v", err)
		}
		big := readAll(t, f, "/big.dat")
		if !bytes.Equal(big[8*hfsTestBlock:], make([]byte, hfsTestBlock)) {
			t.Fatal("overflow extent should be absent")
		}
	})
}

func TestHFSPlusCorruptHeader(t *testing.T) {
	cases := []struct {
		name  string
		setup func([]byte)
		want  string
	}{
		{"version", func(b []byte) { putBE16(b, 1026, 3) }, "version"},
		{"block size", func(b []byte) { putBE32(b, 1024+40, 100) }, "block size"},
		{"zero blocks", func(b []byte) { putBE32(b, 1024+44, 0) }, "zero allocation"},
		{"past range", func(b []byte) { putBE32(b, 1024+44, 1<<30) }, "exceeds range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			img := buildHFSPlusImage()
			tc.setup(img)
			_, err := Probe(memReader{img}, 0, int64(len(img)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestHFSPlusUnit(t *testing.T) {
	if !hfsTime(0).IsZero() {
		t.Fatal("hfsTime(0) must be zero")
	}
	if got := hfsTime(hfsTestDate); got.Year() != 2024 {
		t.Fatalf("hfsTime=%v", got)
	}
	if s := hfsUTF16([]byte{0x00, 'A', 0xD8, 0x3D, 0xDE, 0x09}); s != "A\U0001F609" {
		t.Fatalf("utf16=%q", s)
	}
	if s := hfsUTF16([]byte{0xD8, 0x00}); s != "\uFFFD" {
		t.Fatalf("lone surrogate=%q", s)
	}
	// A key shorter than six bytes must be rejected.
	h := &hfsPlusFS{
		overflow: map[uint32]map[byte][]hfsExtent{},
		items:    map[uint32]*hfsItem{},
		children: map[uint32][]uint32{},
	}
	if err := h.addCatalogRec(make([]byte, 4), make([]byte, 88)); err == nil {
		t.Fatal("expected truncated key error")
	}
	// Duplicate CNIDs keep the first record.
	if err := h.addCatalogRec(hfsCatKey(2, "a"), hfsFolderData(7, 0, 0o40755)); err != nil {
		t.Fatal(err)
	}
	if err := h.addCatalogRec(hfsCatKey(2, "b"), hfsFolderData(7, 0, 0o40755)); err != nil {
		t.Fatal(err)
	}
	if h.items[7].name != "a" {
		t.Fatalf("dup kept %q", h.items[7].name)
	}
	// CNID 0 records are ignored.
	if err := h.addCatalogRec(hfsCatKey(2, "c"), hfsFolderData(0, 0, 0o40755)); err != nil {
		t.Fatal(err)
	}
	if len(h.children[2]) != 1 {
		t.Fatalf("children[2]=%v (duplicates/cnid 0 must not be indexed)", h.children[2])
	}
}
