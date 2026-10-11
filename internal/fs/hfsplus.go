package fs

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// HFS Plus / HFSX on-disk constants (Apple TN1150, linux hfsplus_raw.h).
const (
	hfsSigPlus     = 0x482B // "H+"
	hfsSigX        = 0x4858 // "HX"
	hfsKeyCaseFold = 0xCF   // catalog key comparison: case-insensitive
	hfsKeyBinary   = 0xBC   // catalog key comparison: case-sensitive

	hfsRecFolder       = 1
	hfsRecFile         = 2
	hfsRecFolderThread = 3
	hfsRecFileThread   = 4

	hfsFileCompressed = 0x0080 // file flag: decmpfs-compressed

	hfsRootCNID = 2

	// hfsEpochOffset is the number of seconds from the HFS+ epoch
	// (1904-01-01 00:00:00 UTC) to the Unix epoch.
	hfsEpochOffset = 2082844800

	hfsNodeHeader = 0x01
	hfsNodeLeaf   = 0xFF

	hfsTreeBigKeys    = 0x00000002
	hfsTreeVarIdxKeys = 0x00000004

	// Finder file types we surface as attributes.
	hfsTypeHardlink = 0x686C6E6B // 'hlnk'
	hfsTypeSymlink  = 0x736C6E6B // 'slnk'
)

// hfsExtent is one contiguous run of allocation blocks.
type hfsExtent struct {
	start uint32 // first allocation block (0 = hole)
	count uint32 // number of allocation blocks
}

// hfsFork is the resolved extent list of one file fork.
type hfsFork struct {
	size int64 // logical size in bytes
	exts []hfsExtent
}

// hfsItem is one catalog object (folder or file).
type hfsItem struct {
	name     string
	parent   uint32
	dir      bool
	size     int64
	created  time.Time
	modified time.Time
	mode     uint16 // POSIX mode from the permissions record
	flags    uint16 // file flags (compressed, ...)
	fdType   uint32 // Finder type (files only; 'hlnk'/'slnk' markers)
	fork     hfsFork
}

// hfsPlusFS implements FS for HFS+ (signature "H+") and HFSX ("HX").
//
// The catalog and extent-overflow B-trees are scanned once at open time and
// indexed in memory, matching the full-scan style used by the SQLite reader:
// lookup cost is independent of on-disk tree shape, and no write path or
// mutation log is ever consulted.
type hfsPlusFS struct {
	r       rangeReader
	typ     string // "hfs+" or "hfsx"
	block   int64  // allocation block size
	total   uint32 // allocation block count
	keyType byte   // catalog key comparison (hfsKeyCaseFold/hfsKeyBinary)
	label   string

	items    map[uint32]*hfsItem             // CNID -> object
	children map[uint32][]uint32             // parent CNID -> children in catalog order
	overflow map[uint32]map[byte][]hfsExtent // CNID -> fork type -> overflow extents
}

// newHFSPlus parses an HFS+ volume header (vh is the 512 bytes at offset
// 1024 of the range) and builds a read-only view of the volume.
func newHFSPlus(r rangeReader, vh []byte) (FS, error) {
	if len(vh) < 512 {
		return nil, fmt.Errorf("fs/hfs+: volume header missing")
	}
	h := &hfsPlusFS{r: r}
	switch be16(vh, 0) {
	case hfsSigPlus:
		h.typ = "hfs+"
	case hfsSigX:
		h.typ = "hfsx"
	default:
		return nil, fmt.Errorf("fs/hfs+: bad signature %#04x", be16(vh, 0))
	}
	if ver := be16(vh, 2); ver < 4 || ver > 5 {
		return nil, fmt.Errorf("fs/hfs+: unsupported version %d", ver)
	}
	h.block = int64(be32(vh, 40))
	if h.block < 512 || h.block > 65536 || h.block&(h.block-1) != 0 {
		return nil, fmt.Errorf("fs/hfs+: invalid block size %d", h.block)
	}
	h.total = be32(vh, 44)
	if h.total == 0 {
		return nil, fmt.Errorf("fs/hfs+: zero allocation blocks")
	}
	if size := int64(h.total) * h.block; size > r.size {
		return nil, fmt.Errorf("fs/hfs+: volume (%d bytes) exceeds range (%d bytes)", size, r.size)
	}

	// The extents-overflow tree is read through its own inline extents
	// (an overflow tree never needs itself to be overflowed in practice).
	extFork := h.parseFork(vh[192:272])
	ovfl, err := h.readOverflowTree(extFork)
	if err != nil {
		return nil, err
	}
	h.overflow = ovfl

	// Catalog file: inline extents plus any overflow extents for CNID 4.
	catFork := h.parseFork(vh[272:352])
	catFork.exts = h.mergedExtents(4, 0, catFork.exts)
	cat, err := h.openBtree(catFork, "catalog")
	if err != nil {
		return nil, err
	}
	h.keyType = cat.keyType
	if err := h.scanCatalog(cat); err != nil {
		return nil, err
	}
	if root, ok := h.items[hfsRootCNID]; ok {
		h.label = root.name
	}
	return h, nil
}

// parseFork decodes an hfsplus_fork_raw (80 bytes).
func (h *hfsPlusFS) parseFork(b []byte) hfsFork {
	if len(b) < 80 {
		return hfsFork{}
	}
	f := hfsFork{size: int64(be64(b, 0))}
	for i := 0; i < 8; i++ {
		e := hfsExtent{start: be32(b, 16+i*8), count: be32(b, 20+i*8)}
		if e.count == 0 {
			break
		}
		f.exts = append(f.exts, e)
	}
	return f
}

// mergedExtents returns inline extents followed by overflow extents for
// (cnid, forkType), sorted by logical position (overflow records are stored
// in ascending startBlock order by the format).
func (h *hfsPlusFS) mergedExtents(cnid uint32, forkType byte, inline []hfsExtent) []hfsExtent {
	out := append([]hfsExtent{}, inline...)
	if byType := h.overflow[cnid]; byType != nil {
		out = append(out, byType[forkType]...)
	}
	return out
}

// openBtree opens a B-tree file and reads its header node.
func (h *hfsPlusFS) openBtree(f hfsFork, name string) (*hfsBtree, error) {
	if f.size < 512 {
		return nil, fmt.Errorf("fs/hfs+: %s B-tree too small", name)
	}
	buf := make([]byte, 1024)
	if int64(len(buf)) > f.size {
		buf = buf[:f.size]
	}
	if _, err := h.readFork(f, 0, buf); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("fs/hfs+: read %s B-tree header: %w", name, err)
	}
	if buf[8] != hfsNodeHeader {
		return nil, fmt.Errorf("fs/hfs+: %s B-tree header node missing", name)
	}
	b := &hfsBtree{
		fork:      f,
		nodeSize:  int(be16(buf, 32)), // header record at 14, nodeSize field at 14+18
		root:      be32(buf, 16),      // 14+2
		leafHead:  be32(buf, 24),      // 14+10
		leafCount: be32(buf, 18),      // 14+6
		keyType:   buf[51],            // 14+37
	}
	if b.nodeSize < 512 || b.nodeSize > 32768 || b.nodeSize&(b.nodeSize-1) != 0 {
		return nil, fmt.Errorf("fs/hfs+: %s B-tree invalid node size %d", name, b.nodeSize)
	}
	if int64(b.nodeSize) > f.size {
		return nil, fmt.Errorf("fs/hfs+: %s B-tree node larger than file", name)
	}
	if b.keyType != hfsKeyCaseFold && b.keyType != hfsKeyBinary {
		b.keyType = hfsKeyCaseFold
	}
	return b, nil
}

// hfsBtree is an open HFS+ B-tree file (header fields only).
type hfsBtree struct {
	fork      hfsFork
	nodeSize  int
	root      uint32
	leafHead  uint32
	leafCount uint32
	keyType   byte
}

// readNode reads B-tree node n into a fresh buffer.
func (h *hfsPlusFS) readNode(b *hfsBtree, n uint32) ([]byte, error) {
	if int64(n)+1 > h.forkNodes(b.fork) {
		return nil, fmt.Errorf("fs/hfs+: B-tree node %d out of range", n)
	}
	buf := make([]byte, b.nodeSize)
	off := int64(n) * int64(b.nodeSize)
	if _, err := h.readFork(b.fork, off, buf); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("fs/hfs+: read B-tree node %d: %w", n, err)
	}
	return buf, nil
}

// forkNodes estimates how many B-tree nodes the fork can hold.
func (h *hfsPlusFS) forkNodes(f hfsFork) int64 {
	return f.size / 512 // nodeSize >= 512, loose upper bound
}

// hfsForEachRec calls fn with the key and data of every record in a node.
func hfsForEachRec(node []byte, fn func(key, data []byte) error) error {
	n := int(be16(node, 10))
	if n == 0 {
		return nil
	}
	// The offset table runs backwards from the end of the node: entry i
	// (record start) at len-2*(i+1), plus a free-space entry at len-2*(n+1).
	if len(node) < 14+2*(n+1) {
		return fmt.Errorf("fs/hfs+: truncated B-tree offset table")
	}
	free := int(be16(node, len(node)-2*(n+1)))
	for i := 0; i < n; i++ {
		off := int(be16(node, len(node)-2*(i+1)))
		end := free
		if i+1 < n {
			end = int(be16(node, len(node)-2*(i+2)))
		}
		if off < 14 || end < off || end > len(node) {
			return fmt.Errorf("fs/hfs+: bad record offsets %d:%d", off, end)
		}
		rec := node[off:end]
		if len(rec) < 2 {
			return fmt.Errorf("fs/hfs+: truncated record header")
		}
		keyLen := int(be16(rec, 0))
		keyEnd := 2 + keyLen
		if keyEnd%2 != 0 { // keys are padded to an even length
			keyEnd++
		}
		if keyEnd > len(rec) {
			return fmt.Errorf("fs/hfs+: key overruns record (%d > %d)", keyEnd, len(rec))
		}
		if err := fn(rec[2:keyEnd], rec[keyEnd:]); err != nil {
			return err
		}
	}
	return nil
}

// readOverflowTree scans the extents-overflow B-tree into an index.
func (h *hfsPlusFS) readOverflowTree(f hfsFork) (map[uint32]map[byte][]hfsExtent, error) {
	idx := make(map[uint32]map[byte][]hfsExtent)
	if f.size == 0 {
		return idx, nil
	}
	bt, err := h.openBtree(f, "extents")
	if err != nil {
		return nil, err
	}
	seen := make(map[uint32]bool)
	for n := bt.leafHead; n != 0; {
		if seen[n] {
			return nil, fmt.Errorf("fs/hfs+: extents B-tree leaf cycle at node %d", n)
		}
		seen[n] = true
		node, err := h.readNode(bt, n)
		if err != nil {
			return nil, err
		}
		if node[8] != hfsNodeLeaf {
			return nil, fmt.Errorf("fs/hfs+: extents B-tree node %d is not a leaf", n)
		}
		err = hfsForEachRec(node, func(key, data []byte) error {
			if len(key) != 10 || len(data) < 64 {
				return fmt.Errorf("fs/hfs+: bad extents record (key %d, data %d)", len(key), len(data))
			}
			// Extents key layout (after keyLength): forkType, pad,
			// fileID, startBlock.
			forkType := key[0]
			cnid := be32(key, 2)
			byType := idx[cnid]
			if byType == nil {
				byType = make(map[byte][]hfsExtent)
				idx[cnid] = byType
			}
			for i := 0; i < 8; i++ {
				e := hfsExtent{start: be32(data, i*8), count: be32(data, i*8+4)}
				if e.count == 0 {
					break
				}
				byType[forkType] = append(byType[forkType], e)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		n = be32(node, 0) // fLink
	}
	return idx, nil
}

// scanCatalog walks every catalog leaf and builds the item/child indexes.
func (h *hfsPlusFS) scanCatalog(bt *hfsBtree) error {
	h.items = make(map[uint32]*hfsItem)
	h.children = make(map[uint32][]uint32)
	if bt.leafCount == 0 || bt.leafHead == 0 {
		return nil
	}
	seen := make(map[uint32]bool)
	for n := bt.leafHead; n != 0; {
		if seen[n] {
			return fmt.Errorf("fs/hfs+: catalog B-tree leaf cycle at node %d", n)
		}
		seen[n] = true
		node, err := h.readNode(bt, n)
		if err != nil {
			return err
		}
		if node[8] != hfsNodeLeaf {
			return fmt.Errorf("fs/hfs+: catalog B-tree node %d is not a leaf", n)
		}
		err = hfsForEachRec(node, func(key, data []byte) error {
			return h.addCatalogRec(key, data)
		})
		if err != nil {
			return err
		}
		n = be32(node, 0) // fLink
	}
	return nil
}

// addCatalogRec decodes one folder/file record (thread records are unused:
// the object records already carry parent and name in their keys).
func (h *hfsPlusFS) addCatalogRec(key, data []byte) error {
	if len(key) < 6 {
		return fmt.Errorf("fs/hfs+: truncated catalog key")
	}
	parent := be32(key, 0)
	nameLen := int(be16(key, 4))
	if 6+nameLen*2 > len(key) {
		return fmt.Errorf("fs/hfs+: catalog key name overruns key")
	}
	name := hfsUTF16(key[6 : 6+nameLen*2])

	var it *hfsItem
	switch be16(data, 0) {
	case hfsRecFolder:
		if len(data) < 88 {
			return fmt.Errorf("fs/hfs+: truncated folder record")
		}
		it = &hfsItem{
			name: name, parent: parent, dir: true,
			created: hfsTime(be32(data, 12)), modified: hfsTime(be32(data, 16)),
			mode: be16(data, 42),
		}
	case hfsRecFile:
		if len(data) < 248 {
			return fmt.Errorf("fs/hfs+: truncated file record")
		}
		fork := h.parseFork(data[88:168])
		it = &hfsItem{
			name: name, parent: parent,
			created: hfsTime(be32(data, 12)), modified: hfsTime(be32(data, 16)),
			mode: be16(data, 42), flags: be16(data, 2), fdType: be32(data, 48),
			size: fork.size,
		}
		cnid := be32(data, 8)
		fork.exts = h.mergedExtents(cnid, 0, fork.exts)
		it.fork = fork
	default:
		return nil // folder/file thread records: nothing to index
	}
	cnid := be32(data, 8)
	if cnid == 0 {
		return nil
	}
	if _, dup := h.items[cnid]; dup {
		return nil // first record wins on duplicate CNIDs
	}
	h.items[cnid] = it
	if it.parent != 0 {
		h.children[it.parent] = append(h.children[it.parent], cnid)
	}
	return nil
}

// hfsUTF16 decodes big-endian UTF-16 (with surrogate pairs) to UTF-8.
func hfsUTF16(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		units = append(units, be16(b, i))
	}
	var sb strings.Builder
	for i := 0; i < len(units); i++ {
		u := units[i]
		switch {
		case u >= 0xD800 && u <= 0xDBFF && i+1 < len(units) && units[i+1] >= 0xDC00 && units[i+1] <= 0xDFFF:
			r := rune(u-0xD800)<<10 | rune(units[i+1]-0xDC00) + 0x10000
			sb.WriteRune(r)
			i++
		case u >= 0xD800 && u <= 0xDFFF:
			sb.WriteRune(0xFFFD)
		default:
			sb.WriteRune(rune(u))
		}
	}
	return sb.String()
}

// hfsTime converts an HFS+ date (seconds since 1904-01-01 UTC).
func hfsTime(sec uint32) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(int64(sec)-hfsEpochOffset, 0).UTC()
}

// readFork fills p with fork data at logical off, zero-filling holes.
func (h *hfsPlusFS) readFork(f hfsFork, off int64, p []byte) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("fs/hfs+: negative offset")
	}
	if off >= f.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > f.size-off {
		want = int(f.size - off)
	}
	filled := 0
	var logical int64 // logical start of the next extent
	for _, e := range f.exts {
		start := logical
		length := int64(e.count) * h.block
		logical += length
		if e.count == 0 {
			continue
		}
		end := start + length
		if off >= end {
			continue
		}
		if off < start {
			nzero := want - filled
			if lim := int(start - off); lim < nzero {
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
		seek := off - start
		avail := length - seek
		if avail <= 0 {
			continue
		}
		nread := int64(want - filled)
		if nread > avail {
			nread = avail
		}
		if e.start == 0 {
			// Allocation block 0 holds the volume header, so a zero
			// start marks an unallocated run: hole, zero-fill.
			for i := int64(0); i < nread; i++ {
				p[filled+int(i)] = 0
			}
		} else {
			phys := int64(e.start)*h.block + seek
			buf := make([]byte, nread)
			if err := h.r.readFull(buf, phys); err != nil {
				return filled, fmt.Errorf("fs/hfs+: read data: %w", err)
			}
			copy(p[filled:], buf)
		}
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

// matchName applies the volume's catalog key comparison semantics.
func (h *hfsPlusFS) matchName(want, got string) bool {
	if h.keyType == hfsKeyBinary {
		return want == got
	}
	return strings.EqualFold(want, got)
}

// lookup finds the CNID of name inside parent (0, false when absent).
func (h *hfsPlusFS) lookup(parent uint32, name string) (uint32, bool) {
	for _, cnid := range h.children[parent] {
		it := h.items[cnid]
		if it == nil {
			continue
		}
		if h.matchName(name, it.name) {
			return cnid, true
		}
	}
	return 0, false
}

// resolve walks comps from the root folder.
func (h *hfsPlusFS) resolve(comps []string) (uint32, *hfsItem, error) {
	cnid := uint32(hfsRootCNID)
	it := h.items[cnid]
	if it == nil {
		return 0, nil, fmt.Errorf("fs/hfs+: root folder missing")
	}
	for _, want := range comps {
		if !it.dir {
			return 0, nil, ErrNotFound
		}
		next, ok := h.lookup(cnid, want)
		if !ok {
			return 0, nil, ErrNotFound
		}
		cnid, it = next, h.items[next]
		if it == nil {
			return 0, nil, fmt.Errorf("fs/hfs+: catalog record %d missing", next)
		}
	}
	return cnid, it, nil
}

func (h *hfsPlusFS) entry(name, path string, it *hfsItem) Entry {
	ent := Entry{
		Name: name, Path: path, Dir: it.dir,
		Size: it.size, Modified: it.modified, Created: it.created,
	}
	if it.mode&0o200 == 0 { // owner write bit clear
		ent.Attributes = append(ent.Attributes, "readonly")
	}
	if !it.dir {
		if it.flags&hfsFileCompressed != 0 {
			ent.Attributes = append(ent.Attributes, "compressed")
		}
		switch it.fdType {
		case hfsTypeHardlink:
			ent.Attributes = append(ent.Attributes, "hardlink")
		case hfsTypeSymlink:
			ent.Attributes = append(ent.Attributes, "symlink")
		}
	}
	return ent
}

func (h *hfsPlusFS) Type() string     { return h.typ }
func (h *hfsPlusFS) Label() string    { return h.label }
func (h *hfsPlusFS) TotalSize() int64 { return h.r.size }

func (h *hfsPlusFS) List(path string) ([]Entry, error) {
	comps := splitPath(path)
	cnid, _, err := h.resolve(comps)
	if err != nil {
		return nil, err
	}
	it := h.items[cnid]
	if !it.dir {
		return nil, ErrNotDir
	}
	out := make([]Entry, 0, len(h.children[cnid]))
	for _, child := range h.children[cnid] {
		cit := h.items[child]
		if cit == nil {
			continue
		}
		childPath := joinPath(append(append([]string{}, comps...), cit.name))
		out = append(out, h.entry(cit.name, childPath, cit))
	}
	return out, nil
}

func (h *hfsPlusFS) Stat(path string) (Entry, error) {
	comps := splitPath(path)
	if len(comps) == 0 {
		it := h.items[hfsRootCNID]
		if it == nil {
			return Entry{}, fmt.Errorf("fs/hfs+: root folder missing")
		}
		return h.entry("/", "/", it), nil
	}
	_, it, err := h.resolve(comps)
	if err != nil {
		return Entry{}, err
	}
	// Report the on-disk name, which may differ in case from the query.
	return h.entry(it.name, joinPath(comps), it), nil
}

func (h *hfsPlusFS) ReadAt(path string, off int64, p []byte) (int, error) {
	comps := splitPath(path)
	_, it, err := h.resolve(comps)
	if err != nil {
		return 0, err
	}
	if it.dir {
		return 0, ErrIsDir
	}
	return h.readFork(it.fork, off, p)
}
