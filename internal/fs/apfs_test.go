package fs

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

// --- APFS image builder ----------------------------------------------------
//
// No mkfs.apfs exists on Linux, so the fixture is assembled from the exact
// structures in linux-apfs apfs_raw.h. Layout (4096-byte blocks, 64 total):
//
//	0     container superblock, xid 5 (stale, broken omap pointer)
//	1     container superblock, xid 7 (latest checkpoint)
//	2..4  checkpoint descriptor slots (empty)
//	5     container object map object
//	6     container object map tree root (leaf)
//	7     volume superblock
//	8     volume object map object
//	9     volume object map tree root (leaf)
//	20    fs-tree root (index)
//	21    fs-tree leaf A: root dir, docs, drecs
//	22    fs-tree leaf B: file inodes, drec, extents, decmpfs xattr
//	30    hello.txt data
//	31    readme data

const (
	apfsTestBS       = 4096
	apfsTestBlocks   = 64
	apfsTestXid      = 7
	apfsTestHello    = "Hello, APFS!\n"
	apfsTestReadme   = "readme\n"
	apfsTestFileNS   = uint64(1700000000000000000) // 2023-11-14T22:13:20Z
	apfsTestVolOid   = 100
	apfsTestRootOid  = 200
	apfsTestLeafAOid = 201
	apfsTestLeafBOid = 202
)

func apfsPutLE16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
func apfsPutLE32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func apfsPutLE64(b []byte, off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }

// apfsSetCsum recomputes a block's Fletcher-64 checksum.
func apfsSetCsum(block []byte) {
	apfsPutLE64(block, 0, apfsFletcher64(block[8:]))
}

type apfsRec struct{ key, val []byte }

// apfsBuildNode serializes one APFS b-tree node block (TOC right after the
// header, keys growing forward, values growing backward from the end or
// from the root footer).
func apfsBuildNode(oid, xid uint64, objType, subtype uint32, flags, level uint16, recs []apfsRec) []byte {
	node := make([]byte, apfsTestBS)
	apfsPutLE64(node, 8, oid)
	apfsPutLE64(node, 16, xid)
	apfsPutLE32(node, 24, objType)
	apfsPutLE32(node, 28, subtype)
	apfsPutLE16(node, 32, flags)
	apfsPutLE16(node, 34, level)
	apfsPutLE32(node, 36, uint32(len(recs)))
	entrySize := 8
	if flags&apfsNodeFixedKV != 0 {
		entrySize = 4
	}
	tocBytes := len(recs) * entrySize
	apfsPutLE16(node, 40, 0)                // table_space.off
	apfsPutLE16(node, 42, uint16(tocBytes)) // table_space.len
	apfsPutLE16(node, 48, 0xFFFF)           // key free list: invalid
	apfsPutLE16(node, 52, 0xFFFF)           // value free list: invalid

	toc := apfsNodeHeaderSize
	keyArea := toc + tocBytes
	base := apfsTestBS
	if flags&apfsNodeRoot != 0 {
		base -= apfsBtreeInfoSize
	}
	keyPos, valPos := keyArea, base
	for i, r := range recs {
		koff := keyPos - keyArea
		copy(node[keyPos:], r.key)
		keyPos += len(r.key)
		valPos -= len(r.val)
		if valPos < keyPos {
			panic("apfs fixture: node overflow")
		}
		copy(node[valPos:], r.val)
		voff := base - valPos
		if flags&apfsNodeFixedKV != 0 {
			apfsPutLE16(node, toc+i*4, uint16(koff))
			apfsPutLE16(node, toc+i*4+2, uint16(voff))
		} else {
			apfsPutLE16(node, toc+i*8, uint16(koff))
			apfsPutLE16(node, toc+i*8+2, uint16(len(r.key)))
			apfsPutLE16(node, toc+i*8+4, uint16(voff))
			apfsPutLE16(node, toc+i*8+6, uint16(len(r.val)))
		}
	}
	if flags&apfsNodeRoot != 0 {
		info := node[apfsTestBS-apfsBtreeInfoSize:]
		apfsPutLE32(info, 4, apfsTestBS) // bt_node_size
		apfsPutLE64(info, 24, uint64(len(recs)))
		apfsPutLE64(info, 32, 1)
	}
	apfsSetCsum(node)
	return node
}

// apfsObjHeader writes the shared object header (before btree node fields).
func apfsObjHeader(b []byte, oid, xid uint64, objType, subtype uint32) {
	apfsPutLE64(b, 8, oid)
	apfsPutLE64(b, 16, xid)
	apfsPutLE32(b, 24, objType)
	apfsPutLE32(b, 28, subtype)
}

const (
	apfsObjPhysNX   = 0x40000001 // physical container superblock
	apfsObjPhysOmap = 0x4000000B // physical object map
	apfsObjPhysFS   = 0x4000000D // physical volume superblock
	apfsObjPhysBtn  = 0x40000003 // physical b-tree node
	apfsObjVirtBtn  = 0x00000003 // virtual b-tree node
	apfsSubtypeOmap = 0x0000000B
	apfsSubtypeFS   = 0x0000000E // fs-tree
)

// apfsBuildNX builds a container superblock block.
func apfsBuildNX(xid uint64, omapOid, fsOid uint64) []byte {
	b := make([]byte, apfsTestBS)
	apfsObjHeader(b, 1, xid, apfsObjPhysNX, 0)
	copy(b[32:], apfsNXMagic)
	apfsPutLE32(b, 36, apfsTestBS)
	apfsPutLE64(b, 40, apfsTestBlocks)
	apfsPutLE32(b, 104, 4) // nx_xp_desc_blocks
	apfsPutLE64(b, 112, 1) // nx_xp_desc_base
	apfsPutLE64(b, 160, omapOid)
	apfsPutLE32(b, 180, 100)
	apfsPutLE64(b, 184, fsOid)
	apfsSetCsum(b)
	return b
}

// apfsBuildVol builds a volume superblock block.
func apfsBuildVol(oid, xid, omapOid, rootOid uint64, incompat, fsFlags uint64, name string) []byte {
	b := make([]byte, apfsTestBS)
	apfsObjHeader(b, oid, xid, apfsObjPhysFS, 0)
	copy(b[32:], apfsVolMagic)
	apfsPutLE64(b, 0x38, incompat)
	apfsPutLE64(b, 0x80, omapOid)
	apfsPutLE64(b, 0x88, rootOid)
	apfsPutLE64(b, 0x108, fsFlags)
	copy(b[0x2C0:], name)
	apfsSetCsum(b)
	return b
}

// apfsBuildOmapPhys builds an object map object pointing at its tree root.
func apfsBuildOmapPhys(oid, xid, treeOid uint64) []byte {
	b := make([]byte, apfsTestBS)
	apfsObjHeader(b, oid, xid, apfsObjPhysOmap, 0)
	apfsPutLE64(b, 0x30, treeOid)
	apfsSetCsum(b)
	return b
}

func apfsOmapKey(oid, xid uint64) []byte {
	k := make([]byte, 16)
	apfsPutLE64(k, 0, oid)
	apfsPutLE64(k, 8, xid)
	return k
}

func apfsOmapVal(paddr uint64) []byte {
	v := make([]byte, 16)
	apfsPutLE32(v, 4, apfsTestBS)
	apfsPutLE64(v, 8, paddr)
	return v
}

func apfsKey(ino, typ uint64) []byte {
	k := make([]byte, 8)
	apfsPutLE64(k, 0, ino|(typ<<apfsObjTypeShift))
	return k
}

// apfsDrecKey builds a hashed directory-entry key (name length includes NUL).
func apfsDrecKey(parent uint64, name string) []byte {
	k := make([]byte, 12, 12+len(name)+1)
	apfsPutLE64(k, 0, parent|(apfsCatTypeDirRec<<apfsObjTypeShift))
	apfsPutLE32(k, 8, uint32(len(name)+1)) // hash 0, length with NUL
	return append(k, append([]byte(name), 0)...)
}

func apfsExtentKey(ino, logical uint64) []byte {
	k := append(apfsKey(ino, apfsCatTypeFileExtent), make([]byte, 8)...)
	apfsPutLE64(k, 8, logical)
	return k
}

func apfsExtentVal(length, phys uint64) []byte {
	v := make([]byte, 24)
	apfsPutLE64(v, 0, length)
	apfsPutLE64(v, 8, phys)
	return v
}

func apfsDrecVal(ino uint64, dType uint16) []byte {
	v := make([]byte, 18)
	apfsPutLE64(v, 0, ino)
	apfsPutLE64(v, 8, apfsTestFileNS)
	apfsPutLE16(v, 16, dType)
	return v
}

// apfsInodeVal builds an inode record; files get a dstream xfield.
func apfsInodeVal(parent, privateID uint64, mode uint16, size uint64, withDstream bool) []byte {
	v := make([]byte, 92)
	apfsPutLE64(v, 0, parent)
	apfsPutLE64(v, 8, privateID)
	for _, off := range []int{16, 24, 32, 40} {
		apfsPutLE64(v, off, apfsTestFileNS)
	}
	apfsPutLE16(v, 80, mode)
	if !withDstream {
		return v
	}
	xf := make([]byte, 4+4+40)
	apfsPutLE16(xf, 0, 1)  // one extended field
	apfsPutLE16(xf, 2, 40) // used data
	xf[4] = apfsXfieldTypeDstream
	apfsPutLE16(xf, 6, 40)
	apfsPutLE64(xf, 8, size) // apfs_dstream.size
	return append(v, xf...)
}

// apfsIndexRec builds an index record pointing at a child oid.
func apfsIndexRec(child uint64) []byte {
	v := make([]byte, 8)
	apfsPutLE64(v, 0, child)
	return v
}

// apfsLeafAKeyOrder: inode 2, inode 16, drec docs, drec hello.txt.
func apfsLeafARecords() []apfsRec {
	return []apfsRec{
		{apfsKey(2, apfsCatTypeInode), apfsInodeVal(1, 2, 0o40755, 0, false)},
		{apfsKey(16, apfsCatTypeInode), apfsInodeVal(2, 16, 0o40755, 0, false)},
		{apfsDrecKey(2, "docs"), apfsDrecVal(16, 4)},
		{apfsDrecKey(2, "hello.txt"), apfsDrecVal(17, 8)},
	}
}

// apfsLeafBRecords: file inodes, readme drec, extents, decmpfs xattr.
func apfsLeafBRecords() []apfsRec {
	xattrKey := append(apfsKey(18, apfsCatTypeXattr), 17, 0) // len with NUL
	xattrKey = append(xattrKey, append([]byte(apfsXattrCompressed), 0)...)
	xattrVal := []byte{0x02, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00}
	return []apfsRec{
		{apfsKey(17, apfsCatTypeInode), apfsInodeVal(2, 17, 0o100644, uint64(len(apfsTestHello)), true)},
		{apfsKey(18, apfsCatTypeInode), apfsInodeVal(16, 18, 0o100644, uint64(len(apfsTestReadme)), true)},
		{apfsDrecKey(16, "readme.md"), apfsDrecVal(18, 8)},
		{apfsExtentKey(17, 0), apfsExtentVal(uint64(len(apfsTestHello)), 30)},
		{apfsExtentKey(18, 0), apfsExtentVal(uint64(len(apfsTestReadme)), 31)},
		{xattrKey, xattrVal},
	}
}

func apfsBuildImage() []byte {
	img := make([]byte, apfsTestBlocks*apfsTestBS)
	put := func(b int, src []byte) { copy(img[b*apfsTestBS:], src) }

	// Container superblocks: stale block 0 carries a broken omap pointer;
	// the checkpoint scan must adopt block 1 instead.
	put(0, apfsBuildNX(5, 5, 888))
	put(1, apfsBuildNX(apfsTestXid, 5, apfsTestVolOid))

	// Container object map: volume oid 100 -> volume superblock at 7.
	put(5, apfsBuildOmapPhys(2, apfsTestXid, 6))
	put(6, apfsBuildNode(6, apfsTestXid, apfsObjPhysBtn, apfsSubtypeOmap,
		apfsNodeRoot|apfsNodeLeaf|apfsNodeFixedKV, 0,
		[]apfsRec{{apfsOmapKey(apfsTestVolOid, apfsTestXid), apfsOmapVal(7)}}))

	// Volume superblock (case- and normalization-insensitive, unencrypted).
	put(7, apfsBuildVol(7, apfsTestXid, 8, apfsTestRootOid,
		apfsIncompatCaseInsensitive|apfsIncompatNormInsensitive,
		apfsFsUnencrypted, "GoHexAPFS"))

	// Volume object map: fs-tree nodes 200/201/202.
	put(8, apfsBuildOmapPhys(3, apfsTestXid, 9))
	put(9, apfsBuildNode(9, apfsTestXid, apfsObjPhysBtn, apfsSubtypeOmap,
		apfsNodeRoot|apfsNodeLeaf|apfsNodeFixedKV, 0,
		[]apfsRec{
			{apfsOmapKey(apfsTestRootOid, apfsTestXid), apfsOmapVal(20)},
			{apfsOmapKey(apfsTestLeafAOid, apfsTestXid), apfsOmapVal(21)},
			{apfsOmapKey(apfsTestLeafBOid, apfsTestXid), apfsOmapVal(22)},
		}))

	// fs-tree: index root over two leaves.
	put(20, apfsBuildNode(apfsTestRootOid, apfsTestXid, apfsObjVirtBtn, apfsSubtypeFS,
		apfsNodeRoot, 1,
		[]apfsRec{
			{apfsKey(2, apfsCatTypeInode), apfsIndexRec(apfsTestLeafAOid)},
			{apfsKey(17, apfsCatTypeInode), apfsIndexRec(apfsTestLeafBOid)},
		}))
	put(21, apfsBuildNode(apfsTestLeafAOid, apfsTestXid, apfsObjVirtBtn, apfsSubtypeFS,
		apfsNodeLeaf, 0, apfsLeafARecords()))
	put(22, apfsBuildNode(apfsTestLeafBOid, apfsTestXid, apfsObjVirtBtn, apfsSubtypeFS,
		apfsNodeLeaf, 0, apfsLeafBRecords()))

	copy(img[30*apfsTestBS:], apfsTestHello)
	copy(img[31*apfsTestBS:], apfsTestReadme)
	return img
}

// probeAPFS applies fn to a fresh image and returns Probe's FS and error.
func probeAPFS(t *testing.T, fn func(img []byte)) (FS, error) {
	t.Helper()
	img := apfsBuildImage()
	fn(img)
	return Probe(memReader{img}, 0, int64(len(img)))
}

// --- tests -----------------------------------------------------------------

func TestAPFSBasic(t *testing.T) {
	f := memFS(t, apfsBuildImage())
	if f.Type() != "apfs" {
		t.Fatalf("type=%s", f.Type())
	}
	if f.Label() != "GoHexAPFS" {
		t.Fatalf("label=%q", f.Label())
	}
	if f.TotalSize() != apfsTestBlocks*apfsTestBS {
		t.Fatalf("total=%d", f.TotalSize())
	}

	ents, err := f.List("/")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"docs", "hello.txt"} {
		if !contains(ents, name) {
			t.Fatalf("missing %q in %v", name, names(ents))
		}
	}
	docs := findEntry(t, ents, "docs")
	if !docs.Dir || docs.Size != 0 {
		t.Fatalf("docs=%+v", docs)
	}
	hello := findEntry(t, ents, "hello.txt")
	if hello.Dir || hello.Size != int64(len(apfsTestHello)) {
		t.Fatalf("hello=%+v", hello)
	}
	if hello.Modified.Year() != 2023 {
		t.Fatalf("modified=%v", hello.Modified)
	}
	if len(hello.Attributes) != 0 {
		t.Fatalf("hello attrs=%v", hello.Attributes)
	}

	sub, err := f.List("/docs")
	if err != nil {
		t.Fatal(err)
	}
	if len(sub) != 1 || sub[0].Name != "readme.md" || sub[0].Path != "/docs/readme.md" {
		t.Fatalf("docs entries: %+v", sub)
	}
	if attrs := sub[0].Attributes; len(attrs) != 1 || attrs[0] != "compressed" {
		t.Fatalf("readme attrs=%v", attrs)
	}

	root, err := f.Stat("/")
	if err != nil || !root.Dir || root.Name != "/" {
		t.Fatalf("root=%+v err=%v", root, err)
	}
}

func TestAPFSReadsAndLookup(t *testing.T) {
	f := memFS(t, apfsBuildImage())

	if got := readAll(t, f, "/hello.txt"); string(got) != apfsTestHello {
		t.Fatalf("hello=%q", got)
	}
	if got := readAll(t, f, "/docs/readme.md"); string(got) != apfsTestReadme {
		t.Fatalf("readme=%q", got)
	}

	// Case-insensitive volume (CASE_INSENSITIVE incompat flag).
	st, err := f.Stat("/DOCS/README.MD")
	if err != nil {
		t.Fatalf("case-insensitive stat: %v", err)
	}
	if st.Name != "readme.md" {
		t.Fatalf("name=%q", st.Name)
	}

	// Short read near EOF returns the remaining bytes plus io.EOF.
	p := make([]byte, 8)
	n, err := f.ReadAt("/hello.txt", int64(len(apfsTestHello))-3, p)
	if n != 3 || string(p[:3]) != "S!\n" {
		t.Fatalf("tail n=%d err=%v p=%q", n, err, p[:n])
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("tail err=%v", err)
	}
}

func TestAPFSErrors(t *testing.T) {
	f := memFS(t, apfsBuildImage())

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
	if _, err := f.ReadAt("/hello.txt", -1, make([]byte, 1)); err == nil ||
		!strings.Contains(err.Error(), "negative") {
		t.Fatalf("negative offset: %v", err)
	}
	if _, err := f.ReadAt("/hello.txt", int64(len(apfsTestHello)), make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("offset at size: %v", err)
	}
	// Reading a hole-filled tail: extents exist only for the real bytes,
	// a read past the last extent inside the size is zero-filled.
	st, err := f.Stat("/hello.txt")
	if err != nil || st.Size != int64(len(apfsTestHello)) {
		t.Fatalf("stat=%+v err=%v", st, err)
	}
}

func TestAPFSCorrupt(t *testing.T) {
	cases := []struct {
		name  string
		setup func([]byte)
		want  string
	}{
		{"bad container magic", func(b []byte) { b[32] = 'X' }, "unrecognized"},
		{"invalid block size", func(b []byte) { apfsPutLE32(b, 36, 100) }, "invalid block size"},
		{"implausible geometry", func(b []byte) { apfsPutLE64(b, 40, 1<<40) }, "implausible geometry"},
		{"non-contiguous descriptors", func(b []byte) {
			apfsPutLE64(b, 112, 1|(1<<63))
		}, "non-contiguous"},
		{"too many descriptors", func(b []byte) { apfsPutLE32(b, 104, 20001) }, "implausible descriptor"},
		{"no volumes", func(b []byte) {
			nx := b[1*apfsTestBS:]
			apfsPutLE64(nx, 184, 0)
			apfsSetCsum(nx[:apfsTestBS])
		}, "no volumes"},
		{"volume oid unmapped", func(b []byte) {
			nx := b[1*apfsTestBS:]
			apfsPutLE64(nx, 184, 999)
			apfsSetCsum(nx[:apfsTestBS])
		}, "volume oid 999 not in object map"},
		{"stale checkpoint rejected", func(b []byte) {
			// Corrupt block 1's checksum: the scan must fall back to the
			// stale block 0 and its unmapped volume oid 888.
			b[1*apfsTestBS+8] ^= 0xFF
		}, "volume oid 888 not in object map"},
		{"omap out of range", func(b []byte) {
			nx := b[1*apfsTestBS:]
			apfsPutLE64(nx, 160, 9999)
			apfsSetCsum(nx[:apfsTestBS])
		}, "out of range"},
		{"bad volume magic", func(b []byte) { b[7*apfsTestBS+32] = 'X' }, "bad volume magic"},
		{"fs-tree root unmapped", func(b []byte) {
			vol := b[7*apfsTestBS:]
			apfsPutLE64(vol, 0x88, 999)
			apfsSetCsum(vol[:apfsTestBS])
		}, "not in object map"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := probeAPFS(t, tc.setup)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestAPFSCorruptNodes(t *testing.T) {
	t.Run("omap tree too deep", func(t *testing.T) {
		_, err := probeAPFS(t, func(img []byte) {
			// Rebuild the container omap root as an index node that
			// points at itself.
			idx := apfsBuildNode(6, apfsTestXid, apfsObjPhysBtn, apfsSubtypeOmap,
				apfsNodeRoot|apfsNodeFixedKV, 1,
				[]apfsRec{{apfsOmapKey(apfsTestVolOid, apfsTestXid), apfsIndexRec(6)}})
			copy(img[6*apfsTestBS:], idx)
		})
		if err == nil || !strings.Contains(err.Error(), "too deep") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("corrupt node table of contents", func(t *testing.T) {
		_, err := probeAPFS(t, func(img []byte) {
			apfsPutLE16(img[21*apfsTestBS:], 40, 0xFF00) // table_space.off
			apfsSetCsum(img[21*apfsTestBS : 22*apfsTestBS])
		})
		if err == nil || !strings.Contains(err.Error(), "table of contents") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("implausible record count", func(t *testing.T) {
		_, err := probeAPFS(t, func(img []byte) {
			apfsPutLE32(img[21*apfsTestBS:], 36, 1<<21)
			apfsSetCsum(img[21*apfsTestBS : 22*apfsTestBS])
		})
		if err == nil || !strings.Contains(err.Error(), "implausible record count") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("key out of bounds", func(t *testing.T) {
		_, err := probeAPFS(t, func(img []byte) {
			node := img[21*apfsTestBS:]
			// Leaf, not root: TOC starts at 56, first key offset at 56.
			apfsPutLE16(node, 56, 0xF000)
			apfsSetCsum(node)
		})
		if err == nil || !strings.Contains(err.Error(), "key out of bounds") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("value out of bounds", func(t *testing.T) {
		_, err := probeAPFS(t, func(img []byte) {
			node := img[21*apfsTestBS:]
			// First value offset lives at TOC+6.
			apfsPutLE16(node, 56+4, 0xF000)
			apfsSetCsum(node)
		})
		if err == nil || !strings.Contains(err.Error(), "value out of bounds") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("orphaned subtree is skipped", func(t *testing.T) {
		// Raise leaf B's omap record above the mounted xid: the subtree
		// disappears but the volume still opens.
		f, err := probeAPFS(t, func(img []byte) {
			apfsPutLE64(img[9*apfsTestBS:], 68+2*16+8, 99) // rec 2 xid
			apfsSetCsum(img[9*apfsTestBS : 10*apfsTestBS])
		})
		if err != nil {
			t.Fatalf("Probe: %v", err)
		}
		ents, err := f.List("/")
		if err != nil {
			t.Fatal(err)
		}
		if !contains(ents, "docs") {
			t.Fatalf("root dir lost: %v", names(ents))
		}
		if sub, err := f.List("/docs"); err != nil || len(sub) != 0 {
			t.Fatalf("leaf B should be gone: %v %v", sub, err)
		}
	})
}

// --- unit tests ------------------------------------------------------------

func TestAPFSUnit(t *testing.T) {
	// Fletcher checksum round-trip.
	blk := make([]byte, 64)
	for i := 8; i < 64; i++ {
		blk[i] = byte(i)
	}
	apfsSetCsum(blk)
	if !apfsCsumOK(blk) {
		t.Fatal("valid checksum rejected")
	}
	blk[8] ^= 0xFF
	if apfsCsumOK(blk) {
		t.Fatal("corrupt checksum accepted")
	}
	if apfsCsumOK(make([]byte, 8)) {
		t.Fatal("tiny block accepted")
	}

	// Timestamps.
	if !apfsTime(0).IsZero() {
		t.Fatal("apfsTime(0) must be zero")
	}
	if !apfsTime(1 << 63).IsZero() {
		t.Fatal("overflowing apfsTime must be zero")
	}
	if apfsTime(apfsTestFileNS).Year() != 2023 {
		t.Fatalf("apfsTime=%v", apfsTime(apfsTestFileNS))
	}

	// Dstream xfield parsing.
	xfOK := apfsInodeVal(2, 17, 0o100644, 1234, true)[92:]
	if sz, ok := apfsXfieldDstream(xfOK); !ok || sz != 1234 {
		t.Fatalf("dstream size=%d ok=%v", sz, ok)
	}
	if _, ok := apfsXfieldDstream(nil); ok {
		t.Fatal("empty xfields accepted")
	}
	if _, ok := apfsXfieldDstream([]byte{1, 0, 4, 0}); ok {
		t.Fatal("truncated xfields accepted")
	}
	bad := append([]byte{1, 0, 4, 0, apfsXfieldTypeDstream, 0, 0xF0, 0x0F}, make([]byte, 8)...)
	if _, ok := apfsXfieldDstream(bad); ok {
		t.Fatal("overlong xfield accepted")
	}
	other := append([]byte{1, 0, 4, 0, 0x07, 0, 40, 0}, make([]byte, 40)...)
	if _, ok := apfsXfieldDstream(other); ok {
		t.Fatal("non-dstream xfield accepted")
	}

	// Directory-entry keys.
	a := &apfsFS{hashedKeys: true}
	if name, err := a.drecKey(apfsDrecKey(2, "docs")); err != nil || name != "docs" {
		t.Fatalf("hashed key: %q %v", name, err)
	}
	a.hashedKeys = false
	plain := append(apfsKey(2, apfsCatTypeDirRec), 4, 0, 'a', 'b', 'c', 0)
	if name, err := a.drecKey(plain); err != nil || name != "abc" {
		t.Fatalf("plain key: %q %v", name, err)
	}
	for _, k := range [][]byte{
		make([]byte, 5),
		append(apfsKey(2, apfsCatTypeDirRec), 4, 0, 'a', 'b'), // no NUL
		append(apfsKey(2, apfsCatTypeDirRec), 40, 0, 'a', 0),  // length overrun
	} {
		if _, err := a.drecKey(k); err == nil {
			t.Fatalf("bad plain key accepted: %d bytes", len(k))
		}
	}
	a.hashedKeys = true
	for _, k := range [][]byte{
		make([]byte, 8),
		append(apfsKey(2, apfsCatTypeDirRec), 0, 0, 0, 0, 'x', 0), // len 0
		append(apfsKey(2, apfsCatTypeDirRec), 5, 0, 0, 0, 'x', 0), // no NUL
	} {
		if _, err := a.drecKey(k); err == nil {
			t.Fatalf("bad hashed key accepted: %d bytes", len(k))
		}
	}

	// Xattr keys.
	if n, err := apfsXattrKeyName(append(apfsKey(18, apfsCatTypeXattr), 2, 0, 'a', 0)); err != nil || n != "a" {
		t.Fatalf("xattr key: %q %v", n, err)
	}
	if _, err := apfsXattrKeyName(make([]byte, 4)); err == nil {
		t.Fatal("short xattr key accepted")
	}
	if _, err := apfsXattrKeyName(append(apfsKey(18, apfsCatTypeXattr), 99, 0, 'a', 0)); err == nil {
		t.Fatal("overlong xattr key accepted")
	}
	if _, err := apfsXattrKeyName(append(apfsKey(18, apfsCatTypeXattr), 0, 0)); err == nil {
		t.Fatal("zero-length xattr key accepted")
	}

	// Misc helpers.
	if cString([]byte("abc\x00def")) != "abc" || cString([]byte("abc")) != "abc" {
		t.Fatal("cString")
	}
	if firstOid(make([]byte, 16)) != 0 {
		t.Fatal("firstOid empty")
	}
	zeros := make([]byte, 24)
	apfsPutLE64(zeros, 8, 5)
	if firstOid(zeros) != 5 {
		t.Fatal("firstOid offset")
	}
	if _, err := apfsChildIndex(make([]byte, 4)); err == nil {
		t.Fatal("short index value accepted")
	}
	if v, err := apfsChildIndex([]byte{1, 0, 0, 0, 0, 0, 0, 0}); err != nil || v != 1 {
		t.Fatalf("child index: %d %v", v, err)
	}
}

func TestAPFSNodeUnit(t *testing.T) {
	if _, err := apfsParseNode(make([]byte, 32)); err == nil {
		t.Fatal("short node accepted")
	}
	// Table of contents pushed past the key area.
	bad := apfsBuildNode(1, 1, apfsObjVirtBtn, apfsSubtypeFS, apfsNodeLeaf, 0,
		[]apfsRec{{apfsKey(2, apfsCatTypeInode), make([]byte, 92)}})
	apfsPutLE16(bad, 42, 0) // table_space.len = 0 with one record
	if _, err := apfsParseNode(bad); err == nil {
		t.Fatal("record beyond table space accepted")
	}

	node, err := apfsParseNode(apfsBuildNode(1, 1, apfsObjVirtBtn, apfsSubtypeFS,
		apfsNodeLeaf, 0, []apfsRec{{apfsKey(2, apfsCatTypeInode), make([]byte, 92)}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := node.rec(5); err == nil {
		t.Fatal("out-of-range record accepted")
	}
	k, v, err := node.rec(0)
	if err != nil || len(k) != 8 || len(v) != 92 {
		t.Fatalf("rec: k=%d v=%d err=%v", len(k), len(v), err)
	}
}
