package fs

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// APFS on-disk constants (Apple "Inside APFS", linux-apfs apfs_raw.h).
const (
	apfsNXMagic  = "NXSB" // container superblock
	apfsVolMagic = "APSB" // volume superblock

	// Object types.

	// Catalog (fs-tree) record types, high nibble of the key header.
	apfsCatTypeInode      = 3
	apfsCatTypeXattr      = 4
	apfsCatTypeFileExtent = 8
	apfsCatTypeDirRec     = 9

	// B-tree node flags.
	apfsNodeRoot    = 0x0001
	apfsNodeLeaf    = 0x0002
	apfsNodeFixedKV = 0x0004

	// Object-map value flags.
	apfsOmapValDeleted = 0x00000001

	// Volume incompatible feature flags.
	apfsIncompatCaseInsensitive = 0x1
	apfsIncompatNormInsensitive = 0x8

	// Volume fs flags.
	apfsFsUnencrypted = 0x1

	// Key header bit layout.
	apfsObjIDMask    = 0x0FFFFFFFFFFFFFFF
	apfsObjTypeShift = 60

	// Directory entry name/hash field.
	apfsDrecLenMask = 0x3FF

	// File extent length excludes the flag byte.
	apfsExtentLenMask = 0x00FFFFFFFFFFFFFF

	apfsNodeHeaderSize  = 56 // sizeof(apfs_btree_node_phys)
	apfsBtreeInfoSize   = 40 // footer in root nodes
	apfsOmapKeySize     = 16
	apfsOmapLeafValSize = 16
	apfsChildOidSize    = 8

	apfsRootDirIno = 2

	apfsMaxTreeDepth  = 12
	apfsMaxDescBlocks = 10000

	// Extended field types we care about.
	apfsXfieldTypeDstream = 8

	// Extended attribute names we surface.
	apfsXattrCompressed = "com.apple.decmpfs"
)

// apfsInode is the subset of an inode record we use.
type apfsInode struct {
	parent     uint64
	privateID  uint64
	mode       uint16
	created    time.Time
	modified   time.Time
	accessed   time.Time
	size       int64
	hasDstream bool
}

// apfsChild is one directory entry.
type apfsChild struct {
	name string
	ino  uint64
}

// apfsExtent maps a logical byte range to physical blocks.
type apfsExtent struct {
	logical int64
	length  int64
	phys    uint64
}

// apfsFS implements FS for APFS containers (single volume, the first
// fs_oid in the container superblock).
//
// Like the HFS+ reader, every tree is fully scanned once at open and
// indexed in memory; checkpoint selection honors the container's
// descriptor ring so stale block-0 copies never shadow newer state.
type apfsFS struct {
	r      rangeReader
	bs     int64 // block size
	blocks uint64
	xid    uint64 // mounted transaction id

	label           string
	caseInsensitive bool // CASE_INSENSITIVE incompat flag: name matching
	hashedKeys      bool // hashed drec keys: case- OR normalization-insensitive
	encrypted       bool

	inodes     map[uint64]*apfsInode
	children   map[uint64][]apfsChild
	extents    map[uint64][]apfsExtent
	compressed map[uint64]bool
}

// newAPFS identifies and opens an APFS container in the range.
func newAPFS(r rangeReader) (FS, error) {
	a := &apfsFS{
		r: r, inodes: make(map[uint64]*apfsInode),
		children: make(map[uint64][]apfsChild), extents: make(map[uint64][]apfsExtent),
		compressed: make(map[uint64]bool),
	}

	// The container superblock lives in block 0; its fields fit in 2 KiB
	// regardless of block size, so bootstrap the block size from there.
	head := make([]byte, 2048)
	if err := r.readFull(head, 0); err != nil {
		return nil, fmt.Errorf("fs/apfs: read container superblock: %w", err)
	}
	if string(head[32:36]) != apfsNXMagic {
		return nil, fmt.Errorf("fs/apfs: bad container magic")
	}
	a.bs = int64(le32(head, 36))
	if a.bs < 4096 || a.bs > 65536 || a.bs&(a.bs-1) != 0 {
		return nil, fmt.Errorf("fs/apfs: invalid block size %d", a.bs)
	}
	a.blocks = le64(head, 40)
	if a.blocks == 0 || int64(a.blocks)*a.bs > r.size {
		return nil, fmt.Errorf("fs/apfs: implausible geometry (%d blocks x %d)", a.blocks, a.bs)
	}

	nx, err := a.latestCheckpoint(head)
	if err != nil {
		return nil, err
	}
	a.xid = le64(nx, 16) // apfs_obj_phys: cksum@0, oid@8, xid@16

	// Container object map (physical object) resolves volume oids.
	contOmap, err := a.readOmap(le64(nx, 0xA0))
	if err != nil {
		return nil, fmt.Errorf("fs/apfs: container object map: %w", err)
	}
	volOid := firstOid(nx[0xB8 : 0xB8+100*8])
	if volOid == 0 {
		return nil, fmt.Errorf("fs/apfs: container has no volumes")
	}
	volPaddr, ok := a.omapLookup(contOmap, volOid)
	if !ok {
		return nil, fmt.Errorf("fs/apfs: volume oid %d not in object map", volOid)
	}
	vol, err := a.readBlock(volPaddr)
	if err != nil {
		return nil, fmt.Errorf("fs/apfs: read volume superblock: %w", err)
	}
	if string(vol[32:36]) != apfsVolMagic {
		return nil, fmt.Errorf("fs/apfs: bad volume magic")
	}
	if err := a.parseVolume(vol); err != nil {
		return nil, err
	}
	return a, nil
}

// firstOid returns the first non-zero volume oid in the nx_fs_oid array.
func firstOid(b []byte) uint64 {
	for i := 0; i+8 <= len(b); i += 8 {
		if oid := le64(b, i); oid != 0 {
			return oid
		}
	}
	return 0
}

// latestCheckpoint scans the descriptor ring for the newest valid
// container superblock, mirroring apfs_read_main_super().
func (a *apfsFS) latestCheckpoint(head []byte) ([]byte, error) {
	descBase := le64(head, 0x70)
	descBlocks := le32(head, 0x68)
	if descBase>>63 != 0 {
		return nil, fmt.Errorf("fs/apfs: non-contiguous checkpoint descriptors unsupported")
	}
	if descBlocks > apfsMaxDescBlocks {
		return nil, fmt.Errorf("fs/apfs: implausible descriptor count %d", descBlocks)
	}
	best := head
	bestXid := le64(head, 16)
	for i := uint32(0); i < descBlocks; i++ {
		blk, err := a.readBlock(descBase + uint64(i))
		if err != nil || len(blk) < 512 {
			continue // unreadable descriptor slot: keep what we have
		}
		if string(blk[32:36]) != apfsNXMagic {
			continue
		}
		if xid := le64(blk, 16); xid > bestXid && apfsCsumOK(blk) {
			best, bestXid = blk, xid
		}
	}
	return best, nil
}

// parseVolume reads the volume superblock, object map and fs-tree.
func (a *apfsFS) parseVolume(vol []byte) error {
	incompat := le64(vol, 0x38)
	a.caseInsensitive = incompat&apfsIncompatCaseInsensitive != 0
	a.hashedKeys = incompat&(apfsIncompatCaseInsensitive|apfsIncompatNormInsensitive) != 0
	a.encrypted = le64(vol, 0x108)&apfsFsUnencrypted == 0
	a.label = cString(vol[0x2C0 : 0x2C0+256])

	volOmap, err := a.readOmap(le64(vol, 0x80))
	if err != nil {
		return fmt.Errorf("fs/apfs: volume object map: %w", err)
	}
	rootOid := le64(vol, 0x88)
	rootPaddr, ok := a.omapLookup(volOmap, rootOid)
	if !ok {
		return fmt.Errorf("fs/apfs: fs-tree root oid %d not in object map", rootOid)
	}
	if err := a.walkTree(rootPaddr, volOmap, 0); err != nil {
		return err
	}
	// File extents may live in a dedicated physical fext tree instead of
	// the fs-tree (apfs_fext_tree_oid != 0); when present it wins.
	if fext := le64(vol, 0x408); fext != 0 {
		a.extents = make(map[uint64][]apfsExtent)
		if err := a.walkFextTree(fext, 0); err != nil {
			return err
		}
	}
	for ino := range a.extents {
		exts := a.extents[ino]
		sort.Slice(exts, func(i, j int) bool { return exts[i].logical < exts[j].logical })
	}
	return nil
}

// readOmap reads an object-map object (physical) and returns the newest
// paddr per oid with xid <= the mounted transaction.
func (a *apfsFS) readOmap(paddr uint64) (map[uint64]uint64, error) {
	blk, err := a.readBlock(paddr)
	if err != nil {
		return nil, err
	}
	tree := le64(blk, 0x30) // apfs_omap_phys.om_tree_oid
	out := make(map[uint64]uint64)
	bestXid := make(map[uint64]uint64)
	var visit func(p uint64, depth int) error
	visit = func(p uint64, depth int) error {
		if depth > apfsMaxTreeDepth {
			return fmt.Errorf("fs/apfs: object map tree too deep")
		}
		node, err := a.readBlock(p)
		if err != nil {
			return err
		}
		n, err := apfsParseNode(node)
		if err != nil {
			return err
		}
		for i := 0; i < n.nkeys; i++ {
			k, v, err := n.rec(i)
			if err != nil {
				return err
			}
			if !n.leaf {
				if len(v) < apfsChildOidSize {
					return fmt.Errorf("fs/apfs: bad object map index value")
				}
				if err := visit(le64(v, 0), depth+1); err != nil {
					return err
				}
				continue
			}
			if len(k) < apfsOmapKeySize || len(v) < apfsOmapLeafValSize {
				return fmt.Errorf("fs/apfs: bad object map leaf record")
			}
			oid, xid := le64(k, 0), le64(k, 8)
			flags := le32(v, 0)
			if flags&apfsOmapValDeleted != 0 || xid > a.xid {
				continue
			}
			if prev, seen := bestXid[oid]; seen && prev >= xid {
				continue
			}
			bestXid[oid] = xid
			out[oid] = le64(v, 8)
		}
		return nil
	}
	if tree == 0 {
		return nil, fmt.Errorf("fs/apfs: object map has no tree")
	}
	if err := visit(tree, 0); err != nil {
		return nil, err
	}
	return out, nil
}

// omapLookup resolves a virtual oid inside a loaded object map.
func (a *apfsFS) omapLookup(omap map[uint64]uint64, oid uint64) (uint64, bool) {
	p, ok := omap[oid]
	return p, ok
}

// walkTree recursively scans the fs-tree (virtual nodes via the omap).
func (a *apfsFS) walkTree(paddr uint64, omap map[uint64]uint64, depth int) error {
	if depth > apfsMaxTreeDepth {
		return fmt.Errorf("fs/apfs: fs-tree too deep")
	}
	node, err := a.readBlock(paddr)
	if err != nil {
		return err
	}
	n, err := apfsParseNode(node)
	if err != nil {
		return err
	}
	for i := 0; i < n.nkeys; i++ {
		k, v, err := n.rec(i)
		if err != nil {
			return err
		}
		if !n.leaf {
			child, err := apfsChildIndex(v)
			if err != nil {
				return err
			}
			cp, ok := a.omapLookup(omap, child)
			if !ok {
				continue // orphaned subtree: skip rather than fail the volume
			}
			if err := a.walkTree(cp, omap, depth+1); err != nil {
				return err
			}
			continue
		}
		if err := a.addFSTreeRec(k, v); err != nil {
			return err
		}
	}
	return nil
}

// walkFextTree scans the dedicated file-extent tree (physical nodes).
func (a *apfsFS) walkFextTree(paddr uint64, depth int) error {
	if depth > apfsMaxTreeDepth {
		return fmt.Errorf("fs/apfs: file extent tree too deep")
	}
	node, err := a.readBlock(paddr)
	if err != nil {
		return err
	}
	n, err := apfsParseNode(node)
	if err != nil {
		return err
	}
	for i := 0; i < n.nkeys; i++ {
		k, v, err := n.rec(i)
		if err != nil {
			return err
		}
		if !n.leaf {
			child, err := apfsChildIndex(v)
			if err != nil {
				return err
			}
			if err := a.walkFextTree(child, depth+1); err != nil {
				return err
			}
			continue
		}
		if len(k) < 16 || len(v) < 16 {
			return fmt.Errorf("fs/apfs: bad file extent record")
		}
		a.addExtent(le64(k, 0), le64(k, 8), le64(v, 0), le64(v, 8))
	}
	return nil
}

// apfsChildIndex reads an index node's child pointer.
func apfsChildIndex(v []byte) (uint64, error) {
	if len(v) >= apfsChildOidSize {
		return le64(v, 0), nil
	}
	return 0, fmt.Errorf("fs/apfs: bad index value length %d", len(v))
}

// addExtent appends one file extent (len in bytes, phys in blocks).
func (a *apfsFS) addExtent(privateID, logical, lenAndFlags, phys uint64) {
	length := int64(lenAndFlags & apfsExtentLenMask)
	if length <= 0 {
		return
	}
	a.extents[privateID] = append(a.extents[privateID],
		apfsExtent{logical: int64(logical), length: length, phys: phys})
}

// addFSTreeRec indexes one fs-tree leaf record.
func (a *apfsFS) addFSTreeRec(k, v []byte) error {
	if len(k) < 8 {
		return fmt.Errorf("fs/apfs: truncated fs-tree key")
	}
	hdr := le64(k, 0)
	ino := hdr & apfsObjIDMask
	typ := hdr >> apfsObjTypeShift

	switch typ {
	case apfsCatTypeInode:
		if len(v) < 92 {
			return fmt.Errorf("fs/apfs: truncated inode record")
		}
		it := &apfsInode{
			parent:    le64(v, 0),
			privateID: le64(v, 8),
			created:   apfsTime(le64(v, 16)),
			modified:  apfsTime(le64(v, 24)),
			accessed:  apfsTime(le64(v, 40)),
			mode:      le16(v, 80),
		}
		it.size, it.hasDstream = apfsXfieldDstream(v[92:])
		if it.privateID == 0 {
			it.privateID = ino
		}
		if _, dup := a.inodes[ino]; !dup {
			a.inodes[ino] = it
		}
	case apfsCatTypeDirRec:
		name, err := a.drecKey(k)
		if err != nil {
			return err
		}
		if len(v) < 8 {
			return fmt.Errorf("fs/apfs: truncated directory record")
		}
		a.children[ino] = append(a.children[ino], apfsChild{name: name, ino: le64(v, 0)})
	case apfsCatTypeFileExtent:
		if len(k) < 16 || len(v) < 16 {
			return fmt.Errorf("fs/apfs: bad file extent record")
		}
		a.addExtent(ino, le64(k, 8), le64(v, 0), le64(v, 8))
	case apfsCatTypeXattr:
		name, err := apfsXattrKeyName(k)
		if err != nil {
			return err
		}
		if name == apfsXattrCompressed {
			a.compressed[ino] = true
		}
	}
	return nil
}

// drecKey decodes a directory-entry key (hashed on case- or
// normalization-insensitive volumes). The name is NUL-terminated and the
// stored length includes the terminator.
func (a *apfsFS) drecKey(k []byte) (string, error) {
	if a.hashedKeys {
		if len(k) < 13 {
			return "", fmt.Errorf("fs/apfs: truncated directory key")
		}
		nameLen := int(le32(k, 8) & apfsDrecLenMask) // low 10 bits: length
		if nameLen < 1 || 12+nameLen > len(k) || k[12+nameLen-1] != 0 {
			return "", fmt.Errorf("fs/apfs: bad hashed directory key")
		}
		return string(k[12 : 12+nameLen-1]), nil
	}
	if len(k) < 11 {
		return "", fmt.Errorf("fs/apfs: truncated directory key")
	}
	nameLen := int(le16(k, 8))
	if nameLen < 1 || 10+nameLen > len(k) || k[10+nameLen-1] != 0 {
		return "", fmt.Errorf("fs/apfs: bad directory key")
	}
	return string(k[10 : 10+nameLen-1]), nil
}

// apfsXattrKeyName decodes an extended-attribute key's name.
func apfsXattrKeyName(k []byte) (string, error) {
	if len(k) < 11 {
		return "", fmt.Errorf("fs/apfs: truncated xattr key")
	}
	nameLen := int(le16(k, 8))
	if nameLen == 0 || 10+nameLen > len(k) {
		return "", fmt.Errorf("fs/apfs: bad xattr key length")
	}
	return cString(k[10 : 10+nameLen]), nil
}

// apfsXfieldDstream extracts the data-stream size from an inode's
// extended fields. Returns (0, false) when no dstream field is present
// (directories and some zero-length files).
func apfsXfieldDstream(xf []byte) (int64, bool) {
	if len(xf) < 4 {
		return 0, false
	}
	count := int(le16(xf, 0))
	vstart := 4 + count*4
	if count < 0 || vstart > len(xf) {
		return 0, false
	}
	for i := 0; i < count; i++ {
		typ := xf[4+i*4]
		size := int(le16(xf, 4+i*4+2))
		xlen := (size + 7) &^ 7 // values are padded to 8 bytes
		if xlen < 0 || vstart+xlen > len(xf) {
			return 0, false
		}
		if typ == apfsXfieldTypeDstream && xlen >= 8 {
			return int64(le64(xf, vstart)), true
		}
		vstart += xlen
	}
	return 0, false
}

// apfsTime converts APFS timestamps (nanoseconds since the Unix epoch).
func apfsTime(ns uint64) time.Time {
	if ns == 0 || ns > 0x7FFFFFFFFFFFFFFF {
		return time.Time{}
	}
	return time.Unix(0, int64(ns)).UTC()
}

// apfsParseNode decodes a fixed-size b-tree node block.
type apfsNode struct {
	data    []byte
	bs      int64
	toc     int
	keyArea int
	nkeys   int
	fixed   bool
	root    bool
	leaf    bool
}

func apfsParseNode(block []byte) (*apfsNode, error) {
	if len(block) < apfsNodeHeaderSize {
		return nil, fmt.Errorf("fs/apfs: truncated b-tree node")
	}
	flags := le16(block, 32)
	n := &apfsNode{
		data:  block,
		bs:    int64(len(block)),
		nkeys: int(le32(block, 36)),
		fixed: flags&apfsNodeFixedKV != 0,
		root:  flags&apfsNodeRoot != 0,
		leaf:  flags&apfsNodeLeaf != 0,
	}
	if n.nkeys < 0 || n.nkeys > 1<<20 {
		return nil, fmt.Errorf("fs/apfs: implausible record count %d", n.nkeys)
	}
	n.toc = apfsNodeHeaderSize + int(le16(block, 40))
	n.keyArea = n.toc + int(le16(block, 42))
	entrySize := 8
	if n.fixed {
		entrySize = 4
	}
	if n.toc < apfsNodeHeaderSize || n.keyArea < n.toc ||
		n.toc+n.nkeys*entrySize > n.keyArea || n.keyArea > len(block) {
		return nil, fmt.Errorf("fs/apfs: corrupt node table of contents")
	}
	return n, nil
}

// rec locates record i's key and value inside the node block.
func (n *apfsNode) rec(i int) (key, val []byte, err error) {
	base := n.bs
	if n.root {
		base -= apfsBtreeInfoSize
	}
	if i < 0 || i >= n.nkeys {
		return nil, nil, fmt.Errorf("fs/apfs: record index out of range")
	}
	var koff, klen, voff, vlen int
	if n.fixed {
		e := n.toc + i*4
		koff = n.keyArea + int(le16(n.data, e))
		klen = apfsOmapKeySize
		if n.leaf {
			vlen = apfsOmapLeafValSize
		} else {
			vlen = apfsChildOidSize
		}
		voff = int(base) - int(le16(n.data, e+2))
	} else {
		e := n.toc + i*8
		koff = n.keyArea + int(le16(n.data, e))
		klen = int(le16(n.data, e+2))
		voff = int(base) - int(le16(n.data, e+4))
		vlen = int(le16(n.data, e+6))
	}
	if koff < 0 || klen < 0 || koff+klen > len(n.data) {
		return nil, nil, fmt.Errorf("fs/apfs: key out of bounds (%d+%d)", koff, klen)
	}
	if voff < 0 || vlen < 0 || voff+vlen > len(n.data) {
		return nil, nil, fmt.Errorf("fs/apfs: value out of bounds (%d+%d)", voff, vlen)
	}
	return n.data[koff : koff+klen], n.data[voff : voff+vlen], nil
}

// readBlock reads one container block by physical address.
func (a *apfsFS) readBlock(b uint64) ([]byte, error) {
	if b >= a.blocks {
		return nil, fmt.Errorf("fs/apfs: block %d out of range", b)
	}
	buf := make([]byte, a.bs)
	if err := a.r.readFull(buf, int64(b)*a.bs); err != nil {
		return nil, fmt.Errorf("fs/apfs: read block %d: %w", b, err)
	}
	return buf, nil
}

// apfsCsumOK verifies an object's Fletcher-64 checksum.
func apfsCsumOK(block []byte) bool {
	if len(block) < 16 {
		return false
	}
	return le64(block, 0) == apfsFletcher64(block[8:])
}

// apfsFletcher64 is APFS's variant of the Fletcher checksum (modulo
// 0xFFFFFFFF, little-endian words), as implemented in object.c.
func apfsFletcher64(b []byte) uint64 {
	var sum1, sum2 uint64
	for i := 0; i+4 <= len(b); i += 4 {
		sum1 += uint64(le32(b, i))
		sum2 += sum1
	}
	m := uint64(0xFFFFFFFF)
	c1 := sum1 + sum2
	c1 = 0xFFFFFFFF - c1%m
	c2 := sum1 + c1
	c2 = 0xFFFFFFFF - c2%m
	return c2<<32 | c1
}

// cString trims everything from the first NUL.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i]) //nolint:gosec // G602: IndexByte contract guarantees i < len(b)
	}
	return string(b)
}

// matchName applies the volume's name comparison semantics.
func (a *apfsFS) matchName(want, got string) bool {
	if a.caseInsensitive {
		return strings.EqualFold(want, got)
	}
	return want == got
}

// lookup finds the inode of name inside a directory.
// lookup finds a child by name and reports both its inode and the
// on-disk name (which may differ in case from the query).
func (a *apfsFS) lookup(parent uint64, name string) (uint64, string, bool) {
	for _, c := range a.children[parent] {
		if a.matchName(name, c.name) {
			return c.ino, c.name, true
		}
	}
	return 0, "", false
}

// resolve walks comps from the root directory.
// resolve walks comps from the root directory. It also reports the
// on-disk name of the final component for Stat.
func (a *apfsFS) resolve(comps []string) (uint64, string, error) {
	ino := uint64(apfsRootDirIno)
	last := ""
	it := a.inodes[ino]
	if it == nil {
		return 0, "", fmt.Errorf("fs/apfs: root directory missing")
	}
	for _, want := range comps {
		if it.mode&0xF000 != 0x4000 {
			return 0, "", ErrNotFound
		}
		next, name, ok := a.lookup(ino, want)
		if !ok {
			return 0, "", ErrNotFound
		}
		ino, last = next, name
		it = a.inodes[ino]
		if it == nil {
			return 0, "", fmt.Errorf("fs/apfs: inode %d missing", next)
		}
	}
	return ino, last, nil
}

func (a *apfsFS) entry(name, path string, ino uint64, it *apfsInode) Entry {
	isDir := it.mode&0xF000 == 0x4000
	isSymlink := it.mode&0xF000 == 0xA000
	ent := Entry{
		Name: name, Path: path, Dir: isDir,
		Modified: it.modified, Created: it.created,
	}
	if !isDir {
		ent.Size = it.size
	}
	if it.mode&0o200 == 0 {
		ent.Attributes = append(ent.Attributes, "readonly")
	}
	if isSymlink {
		ent.Attributes = append(ent.Attributes, "symlink")
	}
	if a.compressed[ino] {
		ent.Attributes = append(ent.Attributes, "compressed")
	}
	if a.encrypted && !isDir {
		ent.Attributes = append(ent.Attributes, "encrypted")
	}
	return ent
}

func (a *apfsFS) Type() string     { return "apfs" }
func (a *apfsFS) Label() string    { return a.label }
func (a *apfsFS) TotalSize() int64 { return a.r.size }

func (a *apfsFS) List(path string) ([]Entry, error) {
	comps := splitPath(path)
	ino, _, err := a.resolve(comps)
	if err != nil {
		return nil, err
	}
	if a.inodes[ino].mode&0xF000 != 0x4000 {
		return nil, ErrNotDir
	}
	out := make([]Entry, 0, len(a.children[ino]))
	for _, c := range a.children[ino] {
		it := a.inodes[c.ino]
		if it == nil {
			continue // directory entry without an inode: skip
		}
		childPath := joinPath(append(append([]string{}, comps...), c.name))
		out = append(out, a.entry(c.name, childPath, c.ino, it))
	}
	return out, nil
}

func (a *apfsFS) Stat(path string) (Entry, error) {
	comps := splitPath(path)
	if len(comps) == 0 {
		it := a.inodes[apfsRootDirIno]
		if it == nil {
			return Entry{}, fmt.Errorf("fs/apfs: root directory missing")
		}
		return a.entry("/", "/", apfsRootDirIno, it), nil
	}
	ino, name, err := a.resolve(comps)
	if err != nil {
		return Entry{}, err
	}
	return a.entry(name, joinPath(comps), ino, a.inodes[ino]), nil
}

func (a *apfsFS) ReadAt(path string, off int64, p []byte) (int, error) {
	comps := splitPath(path)
	ino, _, err := a.resolve(comps)
	if err != nil {
		return 0, err
	}
	it := a.inodes[ino]
	if it.mode&0xF000 == 0x4000 {
		return 0, ErrIsDir
	}
	if off < 0 {
		return 0, fmt.Errorf("fs/apfs: negative offset")
	}
	if off >= it.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > it.size-off {
		want = int(it.size - off)
	}
	filled := 0
	for _, e := range a.extents[it.privateID] {
		end := e.logical + e.length
		if off >= end {
			continue
		}
		if off < e.logical {
			nzero := want - filled
			if lim := int(e.logical - off); lim < nzero {
				nzero = lim
			}
			for i := 0; i < nzero; i++ {
				p[filled+i] = 0
			}
			filled += nzero
			off += int64(nzero)
			if filled >= want {
				break
			}
		}
		seek := off - e.logical
		avail := e.length - seek
		if avail <= 0 {
			continue
		}
		nread := int64(want - filled)
		if nread > avail {
			nread = avail
		}
		phys := int64(e.phys)*a.bs + seek
		if phys+nread > a.r.size {
			return filled, fmt.Errorf("fs/apfs: extent beyond end of range")
		}
		buf := make([]byte, nread)
		if err := a.r.readFull(buf, phys); err != nil {
			return filled, fmt.Errorf("fs/apfs: read data: %w", err)
		}
		copy(p[filled:], buf)
		filled += int(nread)
		off += nread
		if filled >= want {
			break
		}
	}
	for filled < want { // trailing hole
		p[filled] = 0
		filled++
	}
	if filled < len(p) {
		return filled, io.EOF
	}
	return filled, nil
}
