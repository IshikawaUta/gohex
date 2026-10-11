package fs

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// NTFS constants.
const (
	ntfsAttrList     = 0x20
	ntfsAttrStdInfo  = 0x10
	ntfsAttrFileName = 0x30
	ntfsAttrData     = 0x80
	ntfsAttrIdxRoot  = 0x90
	ntfsAttrIdxAlloc = 0xA0
	ntfsAttrEnd      = 0xFFFFFFFF

	ntfsRecInUse = 0x01
	ntfsRecDir   = 0x02

	// Attribute header flags.
	ntfsAttrCompressed = 0x0001
	ntfsAttrEncrypted  = 0x4000
	ntfsAttrSparse     = 0x8000
)

type ntfsFS struct {
	r        rangeReader
	bps      int64
	spc      int64
	clus     int64 // cluster size in bytes
	recSize  int64
	mftOff   int64 // byte offset of MFT record 0
	mftRuns  []dataRun
	label    string
	labelled bool

	mu   sync.Mutex
	recs map[uint64]*ntfsRecord // record cache
	dirs map[uint64][]ntfsChild // directory listing cache
}

type dataRun struct {
	vcn    int64 // starting logical cluster (relative to runlist start)
	length int64 // clusters
	lcn    int64 // physical cluster (-1 = sparse)
}

func newNTFS(r rangeReader, head []byte) (FS, error) {
	if len(head) < 512 || head[510] != 0x55 || head[511] != 0xAA {
		return nil, fmt.Errorf("fs/ntfs: missing boot signature")
	}
	n := &ntfsFS{r: r, recs: make(map[uint64]*ntfsRecord), dirs: make(map[uint64][]ntfsChild)}
	n.bps = int64(le16(head, 0x0B))
	n.spc = int64(head[0x0D])
	if n.bps < 256 || n.bps > 4096 || n.bps&(n.bps-1) != 0 {
		return nil, fmt.Errorf("fs/ntfs: invalid sector size %d", n.bps)
	}
	if n.spc == 0 || n.spc&(n.spc-1) != 0 {
		return nil, fmt.Errorf("fs/ntfs: invalid sectors/cluster %d", n.spc)
	}
	n.clus = n.bps * n.spc

	mftClus := int64(le64(head, 0x30))
	n.mftOff = mftClus * n.clus

	cpr := int8(head[0x40])
	switch {
	case cpr < 0:
		n.recSize = 1 << (-cpr) // negative: power of two bytes
	case cpr > 0:
		n.recSize = int64(cpr) * n.clus
	default:
		n.recSize = 1024
	}
	if n.recSize < 256 || n.recSize > 64<<10 || n.recSize%n.bps != 0 {
		return nil, fmt.Errorf("fs/ntfs: invalid file record size %d", n.recSize)
	}

	// Read MFT record 0 to learn $MFT's own data runs.
	rec0, err := n.readRawRecordAt(n.mftOff)
	if err != nil {
		return nil, fmt.Errorf("fs/ntfs: read MFT record 0: %w", err)
	}
	dataAttr, err := rec0.findAttr(ntfsAttrData, "")
	if err != nil {
		return nil, fmt.Errorf("fs/ntfs: $MFT $DATA: %w", err)
	}
	runs, err := n.decodeRuns(dataAttr)
	if err != nil {
		return nil, fmt.Errorf("fs/ntfs: $MFT runs: %w", err)
	}
	n.mftRuns = runs
	return n, nil
}

func (n *ntfsFS) Type() string     { return "ntfs" }
func (n *ntfsFS) TotalSize() int64 { return n.r.size }

func (n *ntfsFS) Label() string {
	n.mu.Lock()
	if n.labelled {
		l := n.label
		n.mu.Unlock()
		return l
	}
	n.mu.Unlock()
	// $VOLUME (record 3) carries $VOLUME_NAME (0x60); 0x70 is
	// $VOLUME_INFORMATION (version/flags, not a name).
	rec, err := n.loadRecord(3)
	if err != nil {
		return ""
	}
	for _, a := range rec.attrs {
		if a.typ == 0x60 && a.resident {
			name := utf16Decode(a.data())
			n.mu.Lock()
			n.label, n.labelled = name, true
			n.mu.Unlock()
			return name
		}
	}
	n.mu.Lock()
	n.labelled = true
	n.mu.Unlock()
	return ""
}

// readRawRecordAt reads a file record straight from a byte offset (used
// before $MFT runs are known) and applies fixups + attribute parsing.
func (n *ntfsFS) readRawRecordAt(off int64) (*ntfsRecord, error) {
	raw := make([]byte, n.recSize)
	if err := n.r.readFull(raw, off); err != nil {
		return nil, err
	}
	return n.parseRecord(raw, 0)
}

// mapMFT translates an MFT-relative byte offset to a physical offset
// using $MFT's data runs.
func (n *ntfsFS) mapMFT(off int64) (int64, error) {
	vcn := off / n.clus
	byteInClus := off % n.clus
	for _, run := range n.mftRuns {
		if vcn >= run.vcn && vcn < run.vcn+run.length {
			if run.lcn < 0 {
				return 0, fmt.Errorf("fs/ntfs: $MFT sparse (corrupt)")
			}
			return (run.lcn+(vcn-run.vcn))*n.clus + byteInClus, nil
		}
	}
	return 0, fmt.Errorf("fs/ntfs: MFT offset %d outside $MFT runs", off)
}

// loadRecord reads and caches MFT record rec.
func (n *ntfsFS) loadRecord(rec uint64) (*ntfsRecord, error) {
	n.mu.Lock()
	if r, ok := n.recs[rec]; ok {
		n.mu.Unlock()
		return r, nil
	}
	n.mu.Unlock()

	off, err := n.mapMFT(int64(rec) * n.recSize)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, n.recSize)
	if err := n.r.readFull(raw, off); err != nil {
		return nil, fmt.Errorf("fs/ntfs: read record %d: %w", rec, err)
	}
	r, err := n.parseRecord(raw, rec)
	if err != nil {
		return nil, err
	}
	// Follow the attribute list to extension records when present.
	if list := findAttrIn(r.attrs, ntfsAttrList, ""); list != nil {
		ext, err := n.expandAttrList(r, list)
		if err != nil {
			return nil, err
		}
		r.attrs = append(r.attrs, ext...)
	}
	n.mu.Lock()
	n.recs[rec] = r
	n.mu.Unlock()
	return r, nil
}

// expandAttrList loads attributes referenced by $ATTRIBUTE_LIST.
func (n *ntfsFS) expandAttrList(base *ntfsRecord, list *ntfsAttr) ([]ntfsAttr, error) {
	var raw []byte
	if list.resident {
		raw = list.data()
	} else {
		runs, err := n.decodeRuns(list)
		if err != nil {
			return nil, err
		}
		size := list.realSize
		if size <= 0 || size > 64<<20 {
			return nil, fmt.Errorf("fs/ntfs: implausible attr list size %d", size)
		}
		raw = make([]byte, size)
		if err := n.readRuns(raw, runs, list.startVCN); err != nil {
			return nil, err
		}
	}
	var out []ntfsAttr
	seen := map[uint64]bool{base.num: true}
	for off := 0; off+26 <= len(raw); {
		typ := le32(raw, off)
		if typ == ntfsAttrEnd || typ == 0 {
			break
		}
		recLen := int(le32(raw, off+4))
		if recLen < 26 || off+recLen > len(raw) {
			break
		}
		startVCN := int64(le64(raw, off+8))
		ref := le64(raw, off+16) & 0x0000FFFFFFFFFFFF
		if ref != base.num && !seen[ref] {
			seen[ref] = true
			ext, err := n.loadRecordPlain(ref)
			if err != nil {
				return nil, err
			}
			// Take all attributes of the extension of the requested type.
			for _, ea := range ext.attrs {
				if ea.typ == typ {
					ea.extStartVCN = startVCN
					out = append(out, ea)
				}
			}
		}
		off += recLen
	}
	return out, nil
}

// loadRecordPlain reads a record without attribute-list expansion.
func (n *ntfsFS) loadRecordPlain(rec uint64) (*ntfsRecord, error) {
	off, err := n.mapMFT(int64(rec) * n.recSize)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, n.recSize)
	if err := n.r.readFull(raw, off); err != nil {
		return nil, err
	}
	return n.parseRecord(raw, rec)
}

// ntfsAttr is one parsed attribute.
type ntfsAttr struct {
	typ         uint32
	resident    bool
	name        string
	flags       uint16
	id          uint16
	startVCN    int64
	realSize    int64
	allocSize   int64
	content     []byte // resident payload (or nil)
	runsRaw     []byte // non-resident runlist bytes
	extStartVCN int64
}

func (a ntfsAttr) data() []byte { return a.content }

// ntfsRecord is a parsed MFT file record.
type ntfsRecord struct {
	num   uint64
	flags uint16
	attrs []ntfsAttr
}

func (r *ntfsRecord) isDir() bool { return r.flags&ntfsRecDir != 0 }
func (r *ntfsRecord) inUse() bool { return r.flags&ntfsRecInUse != 0 }

func findAttrIn(attrs []ntfsAttr, typ uint32, name string) *ntfsAttr {
	for i := range attrs {
		if attrs[i].typ == typ && (name == "" || attrs[i].name == name) {
			return &attrs[i]
		}
	}
	return nil
}

func (r *ntfsRecord) findAttr(typ uint32, name string) (*ntfsAttr, error) {
	a := findAttrIn(r.attrs, typ, name)
	if a == nil {
		return nil, fmt.Errorf("fs/ntfs: attribute %#x %q not found", typ, name)
	}
	return a, nil
}

// parseRecord validates the "FILE" header, applies USA fixups and walks
// the attribute chain.
func (n *ntfsFS) parseRecord(raw []byte, num uint64) (*ntfsRecord, error) {
	if len(raw) < 48 || string(raw[0:4]) != "FILE" {
		return nil, fmt.Errorf("fs/ntfs: record %d bad magic", num)
	}
	usaOff := int(le16(raw, 4))
	usaCount := int(le16(raw, 6))
	if usaCount < 2 || usaOff+usaCount*2 > len(raw) {
		return nil, fmt.Errorf("fs/ntfs: record %d bad fixup array", num)
	}
	// Apply fixups: restore the real last two bytes of every sector.
	seq := raw[usaOff : usaOff+2]
	sectors := (len(raw) + int(n.bps) - 1) / int(n.bps)
	for i := 1; i < usaCount && i <= sectors; i++ {
		dst := i*int(n.bps) - 2
		if dst+2 > len(raw) {
			break
		}
		if raw[dst] != seq[0] || raw[dst+1] != seq[1] {
			return nil, fmt.Errorf("fs/ntfs: record %d fixup mismatch", num)
		}
		copy(raw[dst:dst+2], raw[usaOff+i*2:usaOff+i*2+2])
	}
	attrsOff := int(le16(raw, 20))
	recFlags := le16(raw, 22)
	usedSize := int(le32(raw, 24))
	if attrsOff < 48 || attrsOff >= len(raw) {
		return nil, fmt.Errorf("fs/ntfs: record %d bad attr offset", num)
	}
	if usedSize > len(raw) {
		usedSize = len(raw)
	}
	rec := &ntfsRecord{num: num, flags: recFlags}
	for off := attrsOff; off+16 <= usedSize; {
		typ := le32(raw, off)
		if typ == ntfsAttrEnd {
			break
		}
		if typ == 0 {
			break // slack
		}
		aLen := int(le32(raw, off+4))
		if aLen < 16 || off+aLen > usedSize || off+aLen > len(raw) {
			break
		}
		a := ntfsAttr{
			typ:   typ,
			flags: le16(raw, off+12),
			id:    le16(raw, off+14),
		}
		isResident := raw[off+8] == 0
		nameLen := int(raw[off+9])
		nameOff := int(raw[off+10])
		if nameOff > 0 && nameLen > 0 && nameOff+nameLen*2 <= aLen {
			a.name = utf16Decode(raw[off+nameOff : off+nameOff+nameLen*2])
		}
		if isResident {
			a.resident = true
			cLen := int(le32(raw, off+16))
			cOff := int(le16(raw, off+20)) // 16-bit value offset (byte 22 is flags)
			if cOff < 0 || cLen < 0 || cOff+cLen > aLen {
				break // corrupt
			}
			a.content = raw[off+cOff : off+cOff+cLen]
		} else {
			a.startVCN = int64(le64(raw, off+16))
			rlOff := int(le16(raw, off+32))
			a.allocSize = int64(le64(raw, off+40))
			a.realSize = int64(le64(raw, off+48))
			if rlOff >= aLen {
				break
			}
			a.runsRaw = raw[off+rlOff : off+aLen]
		}
		rec.attrs = append(rec.attrs, a)
		off += aLen
	}
	return rec, nil
}

// decodeRuns converts a runlist header into data runs. runStartVCN is the
// VCN the runs begin at (attribute start VCN, usually 0).
func (n *ntfsFS) decodeRuns(a *ntfsAttr) ([]dataRun, error) {
	var runs []dataRun
	lcn := int64(0)
	vcn := a.startVCN
	raw := a.runsRaw
	for i := 0; i < len(raw); {
		hdr := raw[i]
		if hdr == 0 {
			break // terminator
		}
		lenBytes := int(hdr & 0x0F)
		offBytes := int(hdr >> 4)
		i++
		if lenBytes == 0 || i+lenBytes+offBytes > len(raw) {
			return nil, fmt.Errorf("fs/ntfs: truncated runlist")
		}
		length := int64(0)
		for j := 0; j < lenBytes; j++ {
			length |= int64(raw[i+j]) << (8 * j)
		}
		i += lenBytes
		if length <= 0 {
			return nil, fmt.Errorf("fs/ntfs: zero run length")
		}
		if offBytes == 0 {
			runs = append(runs, dataRun{vcn: vcn, length: length, lcn: -1})
		} else {
			var rel int64
			for j := 0; j < offBytes; j++ {
				rel |= int64(raw[i+j]) << (8 * j)
			}
			if offBytes < 8 && raw[i+offBytes-1]&0x80 != 0 {
				rel |= -1 << (uint(offBytes) * 8) // sign-extend
			}
			lcn += rel
			if lcn < 0 {
				return nil, fmt.Errorf("fs/ntfs: negative LCN (corrupt)")
			}
			runs = append(runs, dataRun{vcn: vcn, length: length, lcn: lcn})
		}
		i += offBytes
		vcn += length
	}
	return runs, nil
}

// readRuns fills dst from runs starting at the runlist-relative byte
// offset startVCN*clus (used for non-resident $ATTRIBUTE_LIST and
// $INDEX_ALLOCATION payloads).
func (n *ntfsFS) readRuns(dst []byte, runs []dataRun, startVCN int64) error {
	return n.readRunsAt(dst, runs, startVCN*n.clus)
}

// ntfsChild is one directory entry (from $I30 index).
type ntfsChild struct {
	rec     uint64
	name    string
	dir     bool
	size    int64
	mtime   time.Time
	ctime   time.Time
	dosOnly bool
}

// fileNameKey decodes a FILE_NAME attribute payload used as index key.
func fileNameKey(k []byte) (parent uint64, name string, size int64, dir bool, mtime, ctime time.Time, ok bool) {
	if len(k) < 66 {
		return 0, "", 0, false, time.Time{}, time.Time{}, false
	}
	parent = le64(k, 0) & 0x0000FFFFFFFFFFFF
	ctime = ntfsTime(le64(k, 8))
	mtime = ntfsTime(le64(k, 16))
	size = int64(le64(k, 48))
	flags := le32(k, 56)
	dir = flags&0x10000000 != 0
	nameLen := int(k[64])
	if 66+nameLen*2 > len(k) {
		return 0, "", 0, false, time.Time{}, time.Time{}, false
	}
	name = utf16Decode(k[66 : 66+nameLen*2])
	return parent, name, size, dir, mtime, ctime, true
}

func ntfsTime(v uint64) time.Time {
	if v == 0 || v == 0xFFFFFFFFFFFFFFFF {
		return time.Time{}
	}
	// 100ns ticks since 1601-01-01.
	ns := int64(v) - 116444736000000000
	if ns < 0 {
		return time.Time{}
	}
	return time.Unix(0, ns*100).UTC()
}

// listIndex collects children of directory record rec via $I30.
func (n *ntfsFS) listIndex(rec uint64) ([]ntfsChild, error) {
	n.mu.Lock()
	if c, ok := n.dirs[rec]; ok {
		n.mu.Unlock()
		return c, nil
	}
	n.mu.Unlock()

	r, err := n.loadRecord(rec)
	if err != nil {
		return nil, err
	}
	rootAttr := findAttrIn(r.attrs, ntfsAttrIdxRoot, "$I30")
	if rootAttr == nil || !rootAttr.resident {
		return nil, fmt.Errorf("fs/ntfs: record %d has no $I30 index root", rec)
	}
	content := rootAttr.content
	if len(content) < 16+16 {
		return nil, fmt.Errorf("fs/ntfs: short index root")
	}
	nodeSize := int64(le32(content, 8))
	if nodeSize < 512 || nodeSize > 64<<10 {
		nodeSize = 4096
	}

	seen := map[string]bool{}
	var byRec []ntfsChild
	addEntries := func(node []byte) error {
		if len(node) < 16 {
			return nil
		}
		entriesOff := int(le32(node, 0))
		usedSize := int(le32(node, 4))
		if entriesOff < 16 || entriesOff > len(node) {
			return nil
		}
		if usedSize > len(node) {
			usedSize = len(node)
		}
		for off := entriesOff; off+16 <= usedSize; {
			entry := node[off:]
			ref := le64(entry, 0) & 0x0000FFFFFFFFFFFF
			entrySize := int(le16(entry, 8))
			keySize := int(le16(entry, 10))
			eFlags := le16(entry, 12)
			if entrySize < 16 || off+entrySize > usedSize {
				break
			}
			if eFlags&0x0002 != 0 { // subnode: handled by subnodeVCNs
			} else if keySize > 0 && 16+keySize <= entrySize {
				key := entry[16 : 16+keySize]
				parent, name, size, dir, mtime, ctime, ok := fileNameKey(key)
				if ok && parent == rec && name != "" && name != "." && name != ".." {
					// Skip DOS 8.3 duplicates when a Win32 name exists for
					// the same record; keep DOS-only names.
					ns := key[65]
					keyID := fmt.Sprintf("%d/%s", ref, strings.ToLower(name))
					if !seen[keyID] {
						seen[keyID] = true
						byRec = append(byRec, ntfsChild{
							rec: ref, name: name, dir: dir,
							size: size, mtime: mtime, ctime: ctime,
							dosOnly: ns == 2,
						})
					}
				}
			}
			off += entrySize
			if eFlags&0x0001 != 0 { // last entry of this node
				break
			}
		}
		// Collect subnode VCNs separately for BFS.
		return nil
	}

	// Root node (INDEX_HDR follows the 16-byte INDEX_ROOT header).
	if err := addEntries(content[16:]); err != nil {
		return nil, err
	}

	// Large indexes: BFS over $INDEX_ALLOCATION nodes.
	allocAttr := findAttrIn(r.attrs, ntfsAttrIdxAlloc, "$I30")
	if allocAttr != nil && !allocAttr.resident {
		runs, err := n.decodeRuns(allocAttr)
		if err != nil {
			return nil, err
		}
		alloc := make([]byte, allocAttr.realSize)
		if int64(len(alloc)) > 64<<20 {
			return nil, fmt.Errorf("fs/ntfs: index allocation too large (%d)", len(alloc))
		}
		if len(alloc) > 0 {
			if err := n.readRuns(alloc, runs, allocAttr.startVCN); err != nil {
				return nil, err
			}
		}
		// Find subnode VCNs from every visited node, starting at the root.
		visited := map[int64]bool{}
		queue := subnodeVCNs(content[16:])
		for len(queue) > 0 {
			vcn := queue[0]
			queue = queue[1:]
			if visited[vcn] {
				continue
			}
			visited[vcn] = true
			off := vcn * nodeSize
			if off < 0 || off+16 > int64(len(alloc)) {
				continue
			}
			node := alloc[off:]
			if int64(len(node)) > nodeSize {
				node = node[:nodeSize]
			}
			hdr, err := n.decodeINDX(node)
			if err != nil {
				return nil, err
			}
			if err := addEntries(hdr); err != nil {
				return nil, err
			}
			queue = append(queue, subnodeVCNs(hdr)...)
		}
	}

	// Drop DOS-only duplicates when the record has a Win32 name too.
	win32 := map[uint64]bool{}
	for _, c := range byRec {
		if !c.dosOnly {
			win32[c.rec] = true
		}
	}
	out := make([]ntfsChild, 0, len(byRec))
	for _, c := range byRec {
		if c.dosOnly && win32[c.rec] {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].name) < strings.ToLower(out[j].name)
	})
	n.mu.Lock()
	n.dirs[rec] = out
	n.mu.Unlock()
	return out, nil
}

// decodeINDX validates an INDEX_ALLOCATION record ("INDX"), applies its
// USA fixups and returns the embedded INDEX_HDR (record bytes 0x18..).
func (n *ntfsFS) decodeINDX(raw []byte) ([]byte, error) {
	if len(raw) < 0x18+16 || string(raw[0:4]) != "INDX" {
		return nil, fmt.Errorf("fs/ntfs: bad INDX magic")
	}
	usaOff := int(le16(raw, 4))
	usaCnt := int(le16(raw, 6))
	if usaCnt < 2 || usaOff+usaCnt*2 > len(raw) {
		return nil, fmt.Errorf("fs/ntfs: bad INDX fixup array")
	}
	seq := raw[usaOff : usaOff+2]
	sectors := (len(raw) + int(n.bps) - 1) / int(n.bps)
	for i := 1; i < usaCnt && i <= sectors; i++ {
		dst := i*int(n.bps) - 2
		if dst+2 > len(raw) {
			break
		}
		if raw[dst] != seq[0] || raw[dst+1] != seq[1] {
			return nil, fmt.Errorf("fs/ntfs: INDX fixup mismatch")
		}
		copy(raw[dst:dst+2], raw[usaOff+i*2:usaOff+i*2+2])
	}
	return raw[0x18:], nil
}

func subnodeVCNs(node []byte) []int64 {
	if len(node) < 16 {
		return nil
	}
	entriesOff := int(le32(node, 0))
	usedSize := int(le32(node, 4))
	if entriesOff < 16 || entriesOff > len(node) {
		return nil
	}
	if usedSize > len(node) {
		usedSize = len(node)
	}
	var subs []int64
	for off := entriesOff; off+16 <= usedSize; {
		entry := node[off:]
		entrySize := int(le16(entry, 8))
		eFlags := le16(entry, 12)
		if entrySize < 16 || off+entrySize > usedSize {
			break
		}
		if eFlags&0x0002 != 0 && entrySize >= 24 {
			subs = append(subs, int64(le64(entry, entrySize-8)))
		}
		off += entrySize
		if eFlags&0x0001 != 0 {
			break
		}
	}
	return subs
}

// resolve walks comps from the root directory (record 5).
func (n *ntfsFS) resolve(comps []string) (uint64, *ntfsRecord, error) {
	rec := uint64(5)
	var r *ntfsRecord
	for _, want := range comps {
		ch, err := n.listIndex(rec)
		if err != nil {
			return 0, nil, err
		}
		found := false
		for _, c := range ch {
			if strings.EqualFold(c.name, want) {
				rec = c.rec
				found = true
				break
			}
		}
		if !found {
			return 0, nil, ErrNotFound
		}
	}
	var err error
	r, err = n.loadRecord(rec)
	if err != nil {
		return 0, nil, err
	}
	if !r.inUse() {
		return 0, nil, ErrNotFound
	}
	return rec, r, nil
}

func (n *ntfsFS) childEntry(comps []string, c ntfsChild) Entry {
	return Entry{
		Name: c.name, Path: joinPath(comps), Dir: c.dir,
		Size: c.size, Modified: c.mtime, Created: c.ctime,
	}
}

func (n *ntfsFS) List(path string) ([]Entry, error) {
	comps := splitPath(path)
	rec, r, err := n.resolve(comps)
	if err != nil {
		return nil, err
	}
	if !r.isDir() {
		return nil, ErrNotDir
	}
	ch, err := n.listIndex(rec)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(ch))
	for _, c := range ch {
		childPath := joinPath(append(append([]string{}, comps...), c.name))
		e := n.childEntry(comps, c)
		e.Path = childPath
		out = append(out, e)
	}
	return out, nil
}

func (n *ntfsFS) Stat(path string) (Entry, error) {
	comps := splitPath(path)
	if len(comps) == 0 {
		return Entry{Name: "/", Path: "/", Dir: true}, nil
	}
	parent := comps[:len(comps)-1]
	want := comps[len(comps)-1]
	prec, pr, err := n.resolve(parent)
	if err != nil {
		return Entry{}, err
	}
	if !pr.isDir() {
		return Entry{}, ErrNotFound
	}
	ch, err := n.listIndex(prec)
	if err != nil {
		return Entry{}, err
	}
	for _, c := range ch {
		if strings.EqualFold(c.name, want) {
			return n.childEntry(comps, c), nil
		}
	}
	return Entry{}, ErrNotFound
}

// readData fills p from the unnamed $DATA attribute of record rec.
func (n *ntfsFS) readData(r *ntfsRecord, off int64, p []byte) (int, error) {
	a := findAttrIn(r.attrs, ntfsAttrData, "")
	if a == nil {
		return 0, io.EOF // file with no unnamed stream (size 0)
	}
	if a.flags&ntfsAttrCompressed != 0 || a.flags&ntfsAttrEncrypted != 0 {
		return 0, fmt.Errorf("fs/ntfs: compressed/encrypted data not supported")
	}
	size := a.realSize
	if a.resident {
		size = int64(len(a.content))
	}
	if off >= size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > size-off {
		want = int(size - off)
	}
	if a.resident {
		copy(p, a.content[off:off+int64(want)])
	} else {
		runs, err := n.decodeRuns(a)
		if err != nil {
			return 0, err
		}
		buf := make([]byte, want)
		if err := n.readRunsAt(buf, runs, off); err != nil {
			return 0, err
		}
		copy(p, buf)
	}
	if want < len(p) {
		return want, io.EOF
	}
	return want, nil
}

// readRunsAt reads file-relative byte range [off, off+len(dst)) via runs.
func (n *ntfsFS) readRunsAt(dst []byte, runs []dataRun, off int64) error {
	vcn := off / n.clus
	byteIn := off % n.clus
	filled := 0
	for filled < len(dst) {
		var run *dataRun
		for i := range runs {
			if vcn >= runs[i].vcn && vcn < runs[i].vcn+runs[i].length {
				run = &runs[i]
				break
			}
		}
		if run == nil {
			return fmt.Errorf("fs/ntfs: VCN %d outside runlist", vcn)
		}
		clusterBytes := int(n.clus)
		availInCluster := clusterBytes - int(byteIn)
		want := len(dst) - filled
		if want > availInCluster {
			want = availInCluster
		}
		if run.lcn < 0 {
			for k := 0; k < want; k++ {
				dst[filled+k] = 0
			}
		} else {
			phys := (run.lcn+(vcn-run.vcn))*n.clus + byteIn
			buf := make([]byte, want)
			if err := n.r.readFull(buf, phys); err != nil {
				return fmt.Errorf("fs/ntfs: read: %w", err)
			}
			copy(dst[filled:], buf)
		}
		filled += want
		byteIn += int64(want)
		if byteIn >= n.clus {
			vcn++
			byteIn = 0
		}
	}
	return nil
}

func (n *ntfsFS) ReadAt(path string, off int64, p []byte) (int, error) {
	comps := splitPath(path)
	_, r, err := n.resolve(comps)
	if err != nil {
		return 0, err
	}
	if r.isDir() {
		return 0, ErrIsDir
	}
	if off < 0 {
		return 0, fmt.Errorf("fs/ntfs: negative offset")
	}
	return n.readData(r, off, p)
}

// utf16Decode decodes UTF-16LE to a Go string.
func utf16Decode(b []byte) string {
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		c := rune(uint16(b[i]) | uint16(b[i+1])<<8)
		if c == 0 {
			break
		}
		sb.WriteRune(c)
	}
	return sb.String()
}
