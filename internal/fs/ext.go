package fs

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ext inode mode types.
const (
	extModeTypeMask = 0xF000
	extModeDir      = 0x4000
	extModeReg      = 0x8000
	extModeSymlink  = 0xA000
)

// ext feature flags we understand.
const (
	extFeatFileType   = 0x0002 // dir entries carry file_type
	extFeatExtents    = 0x0040 // inodes use extent trees
	extFeat64bit      = 0x0080 // 64-bit group descriptors
	extFeatInlineData = 0x8000
	extInodeExtents   = 0x00080000 // i_flags: extent-mapped file
	extInodeSizeHigh  = 0x00100000 // i_flags: i_size_high valid
)

type extFS struct {
	r      rangeReader
	block  int64  // block size
	ibits  int64  // inode size
	feats  uint32 // s_feature_incompat
	compat uint32 // s_feature_compat
	descSz int64

	inodeCount uint32
	blockCount uint64
	blkPerGrp  uint32
	inoPerGrp  uint32
	firstBlock int64

	label string

	gdtOff int64 // byte offset of group descriptor table
}

func newExt(r rangeReader, head []byte) (FS, error) {
	if len(head) < 1024+128 {
		return nil, fmt.Errorf("fs/ext: superblock area missing")
	}
	sb := head[1024:]
	if le16(sb, 56) != 0xEF53 {
		return nil, fmt.Errorf("fs/ext: bad magic")
	}
	e := &extFS{r: r}
	e.block = int64(1024) << le32(sb, 24) // s_log_block_size
	if e.block < 1024 || e.block > 65536 {
		return nil, fmt.Errorf("fs/ext: invalid block size %d", e.block)
	}
	e.inodeCount = le32(sb, 0)
	lo := uint64(le32(sb, 4))
	hi := uint64(le32(sb, 0x150)) // s_blocks_count_hi (64bit)
	if le32(sb, 0x60)&extFeat64bit == 0 {
		hi = 0
	}
	e.blockCount = lo | hi<<32
	e.blkPerGrp = le32(sb, 32)
	e.inoPerGrp = le32(sb, 40)
	e.feats = le32(sb, 0x60)         // s_feature_incompat
	e.compat = le32(sb, 0x5C)        // s_feature_compat
	e.descSz = int64(le16(sb, 0xFE)) // s_desc_size
	if e.descSz == 0 {
		e.descSz = 32
	}
	if e.descSz < 32 || e.descSz > 4096 {
		return nil, fmt.Errorf("fs/ext: invalid descriptor size %d", e.descSz)
	}
	rev := le32(sb, 76) // s_rev_level
	e.ibits = 128
	if rev >= 1 {
		e.ibits = int64(le16(sb, 88)) // s_inode_size
	}
	if e.ibits < 128 || e.ibits > 4096 || e.ibits&(e.ibits-1) != 0 {
		return nil, fmt.Errorf("fs/ext: invalid inode size %d", e.ibits)
	}
	e.firstBlock = int64(le32(sb, 20)) // s_first_data_block
	if e.feats&extFeatInlineData != 0 {
		return nil, fmt.Errorf("fs/ext: inline-data inodes not supported")
	}
	if e.inodeCount == 0 || e.blkPerGrp == 0 || e.inoPerGrp == 0 {
		return nil, fmt.Errorf("fs/ext: implausible geometry")
	}
	e.gdtOff = (e.firstBlock + 1) * e.block
	e.label = strings.TrimRight(string(sb[0x78:0x88]), "\x00")
	return e, nil
}

func (e *extFS) Type() string {
	switch {
	case e.feats&extFeatExtents != 0:
		return "ext4"
	case e.compat&0x4 != 0: // has_journal
		return "ext3"
	default:
		return "ext2"
	}
}

func (e *extFS) Label() string    { return e.label }
func (e *extFS) TotalSize() int64 { return e.r.size }

func (e *extFS) blockOff(b uint64) int64 { return int64(b) * e.block }

// readBlock fills buf with the full contents of block b.
func (e *extFS) readBlock(buf []byte, b uint64) error {
	if err := e.r.readFull(buf, e.blockOff(b)); err != nil {
		return fmt.Errorf("fs/ext: read block %d: %w", b, err)
	}
	return nil
}

// extGroup describes one block group descriptor (fields we need).
type extGroup struct {
	inodeTable uint64
}

// group returns the descriptor for group g.
func (e *extFS) group(g uint32) (extGroup, error) {
	off := e.gdtOff + int64(g)*e.descSz
	b := make([]byte, e.descSz)
	if err := e.r.readFull(b, off); err != nil {
		return extGroup{}, fmt.Errorf("fs/ext: read group desc %d: %w", g, err)
	}
	lo := uint64(le32(b, 8)) // bg_inode_table_lo
	var hi uint64
	if e.feats&extFeat64bit != 0 && e.descSz >= 48 {
		hi = uint64(le32(b, 40)) // bg_inode_table_hi
	}
	return extGroup{inodeTable: lo | hi<<32}, nil
}

// extInode is the subset of an inode we use.
type extInode struct {
	mode  uint16
	size  int64
	mtime time.Time
	ctime time.Time
	nlink uint16
	flags uint32
	links []extBlock // logical byte ranges
}

type extBlock struct {
	logical int64 // logical offset in file
	length  int64
	phys    uint64
}

// inode reads inode number ino (1-based).
func (e *extFS) inode(ino uint32) (extInode, error) {
	if ino == 0 {
		return extInode{}, fmt.Errorf("fs/ext: inode 0")
	}
	g := (ino - 1) / e.inoPerGrp
	idx := (ino - 1) % e.inoPerGrp
	gd, err := e.group(g)
	if err != nil {
		return extInode{}, err
	}
	off := int64(gd.inodeTable)*e.block + int64(idx)*e.ibits
	b := make([]byte, e.ibits)
	if err := e.r.readFull(b, off); err != nil {
		return extInode{}, fmt.Errorf("fs/ext: read inode %d: %w", ino, err)
	}
	n := extInode{
		mode:  le16(b, 0),
		size:  int64(le32(b, 4)),
		mtime: extTime(le32(b, 16)),
		ctime: extTime(le32(b, 12)),
		nlink: le16(b, 26),
		flags: le32(b, 32),
	}
	if n.mode == 0 || n.nlink == 0 {
		return extInode{}, fmt.Errorf("fs/ext: inode %d unused/corrupt", ino)
	}
	if n.flags&extInodeSizeHigh != 0 {
		n.size |= int64(le32(b, 108)) << 32
	}
	if n.flags&extInodeExtents != 0 || n.mode&extModeTypeMask == extModeDir && e.feats&extFeatExtents != 0 {
		blocks, err := e.extentTree(b[40:100], 0)
		if err != nil {
			return extInode{}, err
		}
		n.links = blocks
	} else {
		blocks, err := e.indirectTree(b, 0, 0, n.size)
		if err != nil {
			return extInode{}, err
		}
		n.links = blocks
	}
	return n, nil
}

// extentTree decodes an extent header node (in-page form) into logical
// byte ranges. depth>0 nodes are index nodes referencing child blocks.
func (e *extFS) extentTree(node []byte, depth int) ([]extBlock, error) {
	if depth > 5 {
		return nil, fmt.Errorf("fs/ext: extent tree too deep")
	}
	if le16(node, 0) != 0xF30A {
		return nil, fmt.Errorf("fs/ext: bad extent magic")
	}
	entries := int(le16(node, 2))
	max := int(le16(node, 4))
	if entries < 0 || entries > max || entries > 512 {
		return nil, fmt.Errorf("fs/ext: implausible extent count %d/%d", entries, max)
	}
	ehDepth := int(le16(node, 6))
	var out []extBlock
	for i := 0; i < entries; i++ {
		ent := node[12+i*12:]
		if len(ent) < 12 {
			break
		}
		if ehDepth == 0 {
			logical := int64(le32(ent, 0))
			length := int64(le16(ent, 4))
			if length&0x8000 != 0 { // uninitialized extent: zero-fill
				continue
			}
			phys := uint64(le16(ent, 6))<<32 | uint64(le32(ent, 8))
			out = append(out, extBlock{logical: logical * e.block, length: length * e.block, phys: phys})
		} else {
			logical := int64(le32(ent, 0))
			leaf := uint64(le32(ent, 4)) | uint64(le16(ent, 8))<<32
			buf := make([]byte, e.block)
			if err := e.readBlock(buf, leaf); err != nil {
				return nil, err
			}
			child, err := e.extentTree(buf, depth+1)
			if err != nil {
				return nil, err
			}
			// Child logicals are relative to this subtree's base.
			for i := range child {
				child[i].logical += logical * e.block
			}
			out = append(out, child...)
		}
	}
	return out, nil
}

// indirectTree decodes classic block maps (direct + single/double/triple
// indirect) for non-extent inodes.
func (e *extFS) indirectTree(b []byte, depth int, logical int64, size int64) ([]extBlock, error) {
	if depth > 3 {
		return nil, nil
	}
	var out []extBlock
	// i_block[0..11]: direct data pointers.
	for i := 0; i < 12; i++ {
		phys := uint64(le32(b, 40+i*4))
		if phys == 0 {
			logical += e.block // sparse hole
			continue
		}
		out = append(out, extBlock{logical: logical, length: e.block, phys: phys})
		logical += e.block
	}
	// i_block[12..14]: single/double/triple indirect.
	for i := 12; i < 15; i++ {
		phys := uint64(le32(b, 40+i*4))
		if phys == 0 {
			break
		}
		if err := e.walkIndirect(phys, i-12, logical, size, &out); err != nil {
			return out, err
		}
		// Span covered by this indirection level: block * per^(level+1).
		per := e.block / 4
		span := e.block
		for d := 0; d <= i-12; d++ {
			span *= per
		}
		logical += span
		if size > 0 && logical >= size {
			break
		}
	}
	return out, nil
}

// walkIndirect reads an indirect block and follows its pointers.
// depth 0: pointers are data blocks; depth 1: single-indirection blocks,
// depth 2: double-indirection blocks.
func (e *extFS) walkIndirect(phys uint64, depth int, base int64, size int64, out *[]extBlock) error {
	buf := make([]byte, e.block)
	if err := e.readBlock(buf, phys); err != nil {
		return fmt.Errorf("fs/ext: read indirect block: %w", err)
	}
	per := e.block / 4
	// Bytes covered by one pointer at this depth.
	span := e.block
	for d := 0; d < depth; d++ {
		span *= per
	}
	for j := 0; j < int(per); j++ {
		blkLogical := base + int64(j)*span
		if size > 0 && blkLogical >= size {
			break
		}
		p := uint64(le32(buf, j*4))
		if p == 0 {
			continue
		}
		if depth == 0 {
			*out = append(*out, extBlock{logical: blkLogical, length: e.block, phys: p})
			continue
		}
		if err := e.walkIndirect(p, depth-1, blkLogical, size, out); err != nil {
			return err
		}
	}
	return nil
}

func extTime(sec uint32) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(int64(sec), 0).UTC()
}

// readAt reads from the mapped blocks at logical off.
func (e *extFS) readAt(n extInode, off int64, p []byte) (int, error) {
	if off >= n.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > n.size-off {
		want = int(n.size - off)
	}
	filled := 0
	for _, blk := range n.links {
		end := blk.logical + blk.length
		if off >= end {
			continue
		}
		if off < blk.logical {
			// Sparse hole: zero-fill up to the next mapped byte. The hole
			// may end inside this same extent, so fall through afterwards
			// (off lands exactly on blk.logical) instead of skipping it.
			nzero := int(int64(want) - int64(filled))
			if lim := int(blk.logical - off); lim < nzero {
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
		seek := off - blk.logical
		avail := blk.length - seek
		if avail <= 0 {
			continue
		}
		nread := int64(want - filled)
		if nread > avail {
			nread = avail
		}
		physOff := e.blockOff(blk.phys) + seek
		buf := make([]byte, nread)
		if err := e.r.readFull(buf, physOff); err != nil {
			return filled, fmt.Errorf("fs/ext: read data: %w", err)
		}
		copy(p[filled:], buf)
		filled += int(nread)
		off += nread
		if filled >= want {
			break
		}
	}
	// Trailing hole: zero-fill.
	for filled < want {
		p[filled] = 0
		filled++
		off++
	}
	if filled < len(p) {
		return filled, io.EOF
	}
	return filled, nil
}

// extDirEnt is one directory record.
type extDirEnt struct {
	ino  uint32
	name string
	typ  byte
}

func (e *extFS) readDir(n extInode) ([]extDirEnt, error) {
	if n.size == 0 {
		return nil, nil
	}
	buf := make([]byte, n.size)
	if _, err := e.readAt(n, 0, buf); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	var out []extDirEnt
	for off := 0; off+8 <= len(buf); {
		ino := le32(buf, off)
		recLen := int(le16(buf, off+4))
		nameLen := int(buf[off+6])
		typ := buf[off+7]
		if recLen < 8 || off+recLen > len(buf) {
			break
		}
		if ino != 0 && nameLen > 0 && nameLen <= recLen-8 {
			name := string(buf[off+8 : off+8+nameLen])
			if name != "." && name != ".." {
				out = append(out, extDirEnt{ino: ino, name: name, typ: typ})
			}
		}
		off += recLen
	}
	return out, nil
}

// node resolves comps from the root; returns inode number + inode.
func (e *extFS) resolve(comps []string) (uint32, extInode, error) {
	ino := uint32(2) // root
	n, err := e.inode(ino)
	if err != nil {
		return 0, extInode{}, err
	}
	for _, want := range comps {
		if n.mode&extModeTypeMask != extModeDir {
			return 0, extInode{}, ErrNotFound
		}
		ents, err := e.readDir(n)
		if err != nil {
			return 0, extInode{}, err
		}
		found := false
		for _, de := range ents {
			if de.name == want {
				n2, err := e.inode(de.ino)
				if err != nil {
					return 0, extInode{}, err
				}
				ino, n = de.ino, n2
				found = true
				break
			}
		}
		if !found {
			return 0, extInode{}, ErrNotFound
		}
	}
	return ino, n, nil
}

func extTypeAttr(mode uint16) []string {
	switch mode & extModeTypeMask {
	case extModeSymlink:
		return []string{"symlink"}
	case 0xC000: // S_IFSOCK
		return []string{"socket"}
	case 0x1000: // S_IFIFO
		return []string{"fifo"}
	case 0x2000: // S_IFCHR
		return []string{"chardev"}
	case 0x6000: // S_IFBLK
		return []string{"blockdev"}
	}
	return nil
}

func (e *extFS) entry(name, path string, n extInode) Entry {
	isDir := n.mode&extModeTypeMask == extModeDir
	ent := Entry{
		Name: name, Path: path, Dir: isDir,
		Size: n.size, Modified: n.mtime, Created: n.ctime,
	}
	ent.Attributes = extTypeAttr(n.mode & extModeTypeMask)
	if n.mode&0x0080 == 0 { // owner write bit (S_IWUSR) clear
		ent.Attributes = append(ent.Attributes, "readonly")
	}
	return ent
}

func (e *extFS) List(path string) ([]Entry, error) {
	comps := splitPath(path)
	_, n, err := e.resolve(comps)
	if err != nil {
		return nil, err
	}
	if n.mode&extModeTypeMask != extModeDir {
		return nil, ErrNotDir
	}
	ents, err := e.readDir(n)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(ents))
	for _, de := range ents {
		child, err := e.inode(de.ino)
		if err != nil {
			continue // skip unreadable/corrupt records
		}
		childPath := joinPath(append(append([]string{}, comps...), de.name))
		out = append(out, e.entry(de.name, childPath, child))
	}
	return out, nil
}

func (e *extFS) Stat(path string) (Entry, error) {
	comps := splitPath(path)
	if len(comps) == 0 {
		return Entry{Name: "/", Path: "/", Dir: true}, nil
	}
	_, n, err := e.resolve(comps)
	if err != nil {
		return Entry{}, err
	}
	return e.entry(comps[len(comps)-1], joinPath(comps), n), nil
}

func (e *extFS) ReadAt(path string, off int64, p []byte) (int, error) {
	comps := splitPath(path)
	_, n, err := e.resolve(comps)
	if err != nil {
		return 0, err
	}
	if n.mode&extModeTypeMask == extModeDir {
		return 0, ErrIsDir
	}
	if off < 0 {
		return 0, fmt.Errorf("fs/ext: negative offset")
	}
	return e.readAt(n, off, p)
}
