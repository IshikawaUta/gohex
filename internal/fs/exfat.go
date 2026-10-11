package fs

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// exFAT reader (read-only).
type exfatFS struct {
	r        rangeReader
	clus     int64 // cluster size in bytes
	fatOff   int64 // byte offset of FAT
	fatLen   int64 // byte length of FAT
	heapOff  int64 // byte offset of cluster heap
	clusCnt  uint32
	rootClus uint32
	label    string
}

// exFAT directory entry types (with IN_USE = 0x80).
const (
	exEntryBitmap  = 0x81
	exEntryUpcase  = 0x82
	exEntryLabel   = 0x83
	exEntryFile    = 0x85
	exEntryStream  = 0xC0
	exEntryName    = 0xC1
	exEntryDeleted = 0x05 // FILE entry with IN_USE cleared
)

func newExFAT(r rangeReader, head []byte) (FS, error) {
	if len(head) < 512 {
		return nil, fmt.Errorf("fs/exfat: too small")
	}
	e := &exfatFS{r: r}
	partOff := le64(head, 64)
	fsLen := le64(head, 72)
	fatOffset := int64(le32(head, 80))
	fatLen := int64(le32(head, 84))
	heap := int64(le32(head, 88))
	clusCnt := le32(head, 92)
	rootClus := le32(head, 96)
	// exFAT shifts are single bytes: sector 0x6C, cluster 0x6D.
	bpsShift := int(head[108])
	spcShift := int(head[109])
	if bpsShift < 9 || bpsShift > 12 || spcShift < 0 || spcShift > 16 {
		return nil, fmt.Errorf("fs/exfat: invalid sector/cluster shift %d/%d", bpsShift, spcShift)
	}
	if partOff != 0 {
		return nil, fmt.Errorf("fs/exfat: partitioned exFAT not supported")
	}
	fsBytes := fsLen << bpsShift
	if fsBytes == 0 || fsBytes > uint64(r.size) {
		fsBytes = uint64(r.size)
	}
	_ = fsBytes
	if fatOffset == 0 || heap < fatOffset || rootClus < 2 || clusCnt == 0 {
		return nil, fmt.Errorf("fs/exfat: implausible geometry")
	}
	e.clus = 1 << (bpsShift + spcShift) // cluster = sector << sectors-per-cluster
	e.fatOff = fatOffset * 512          // sector-addressed
	e.fatLen = fatLen * 512
	e.heapOff = heap * 512 // sector-addressed
	e.clusCnt = clusCnt
	e.rootClus = rootClus

	// Validate the boot checksum (first 112 bytes + non-zero bytes up to
	// sector 11). Catches wrong geometry cheaply.
	if err := verifyExfatBootsum(head, r); err != nil {
		return nil, err
	}
	e.label = exfatBootLabel(head)
	return e, nil
}

func verifyExfatBootsum(head []byte, r rangeReader) error {
	// Checksum covers the first 11 sectors of the boot region with a
	// rolling ROR1+add, skipping the mutable VolumeFlags/PercentInUse
	// bytes at global offsets 106,107,112. It is stored (repeated) at
	// sector 11 (offset 11*512) and in the backup copy at sector 11+12.
	region := make([]byte, 11*512)
	if err := r.readFull(region, 0); err != nil {
		return nil // tolerate read failures; not fatal
	}
	want := le32(head, 11*512)
	if want == 0 {
		return nil
	}
	var acc uint32
	for i, b := range region {
		if i == 106 || i == 107 || i == 112 {
			continue
		}
		var carry uint32
		if acc&1 != 0 {
			carry = 0x80000000
		}
		acc = carry + acc>>1 + uint32(b)
	}
	if acc != want {
		return fmt.Errorf("fs/exfat: boot region checksum mismatch")
	}
	return nil
}

func exfatBootLabel(head []byte) string {
	_ = head // exFAT stores the label only as a root directory entry
	return ""
}

func (e *exfatFS) Type() string     { return "exfat" }
func (e *exfatFS) TotalSize() int64 { return e.r.size }

func (e *exfatFS) Label() string {
	ents, err := e.readDirChain(e.rootClus)
	if err != nil {
		return ""
	}
	for _, d := range ents {
		if d.typ&0x7F == exEntryLabel&0x7F && !d.deleted && d.label != "" {
			return d.label
		}
	}
	return ""
}

// fatNext returns the FAT entry for a cluster.
func (e *exfatFS) fatNext(clus uint32) (uint32, error) {
	b := make([]byte, 4)
	if err := e.r.readFull(b, e.fatOff+int64(clus)*4); err != nil {
		return 0, fmt.Errorf("fs/exfat: read FAT: %w", err)
	}
	return le32(b, 0), nil
}

func exFatEOC(v uint32) bool { return v >= 0xFFFFFFF8 }

// chain walks a cluster chain with loop guards.
func (e *exfatFS) chain(clus uint32, limit int64) ([]uint32, error) {
	var out []uint32
	seen := map[uint32]bool{}
	for clus >= 2 && !exFatEOC(clus) && clus != 0xFFFFFFF7 {
		if seen[clus] {
			return out, fmt.Errorf("fs/exfat: cluster loop at %d", clus)
		}
		seen[clus] = true
		out = append(out, clus)
		if int64(len(out)) > limit {
			return out, fmt.Errorf("fs/exfat: chain too long")
		}
		next, err := e.fatNext(clus)
		if err != nil {
			return out, err
		}
		clus = next
	}
	return out, nil
}

func (e *exfatFS) clusterOff(clus uint32) int64 {
	return e.heapOff + int64(clus-2)*e.clus
}

func (e *exfatFS) maxChain() int64 { return int64(e.clusCnt) + 8 }

// exDirItem is a decoded directory entry group (FILE+STREAM+NAMES).
type exDirItem struct {
	typ       byte
	deleted   bool
	isDir     bool
	name      string
	label     string
	clus      uint32
	size      int64
	validSize int64
	mtime     time.Time
	ctime     time.Time
	attrs     uint16
	noChain   bool // no FAT chain: contiguous allocation
}

// readDirChain reads raw directory bytes starting at cluster first.
func (e *exfatFS) readDirChain(first uint32) ([]exDirItem, error) {
	chain, err := e.chain(first, e.maxChain())
	if err != nil {
		return nil, err
	}
	var raw []byte
	tmp := make([]byte, e.clus)
	for _, c := range chain {
		if err := e.r.readFull(tmp, e.clusterOff(c)); err != nil {
			return nil, fmt.Errorf("fs/exfat: read dir cluster: %w", err)
		}
		raw = append(raw, tmp...)
	}
	return exfatParseDir(raw), nil
}

// contigBytes reads a contiguous range (no FAT chain) starting at first.
func (e *exfatFS) contigBytes(first uint32, size int64) ([]byte, error) {
	if size <= 0 || size > 64<<20 {
		return nil, nil
	}
	buf := make([]byte, size)
	off := e.clusterOff(first)
	if err := e.r.readFull(buf, off); err != nil {
		return nil, fmt.Errorf("fs/exfat: read contiguous data: %w", err)
	}
	return buf, nil
}

func exfatParseDir(raw []byte) []exDirItem {
	var out []exDirItem
	var pending *exDirItem
	var nameParts []string

	flush := func() {
		if pending != nil {
			if len(nameParts) > 0 {
				pending.name = strings.Join(nameParts, "")
			}
			if pending.name != "" || pending.label != "" {
				out = append(out, *pending)
			}
		}
		pending = nil
		nameParts = nil
	}

	for off := 0; off+32 <= len(raw); off += 32 {
		d := raw[off:]
		typ := d[0]
		if typ == 0 {
			break // end of directory
		}
		deleted := typ&0x80 == 0
		// Deleted secondaries clear IN_USE (bit 7); all types below are
		// still parsed whether the entry is live or deleted.
		switch typ & 0x7F {
		case exEntryFile & 0x7F: // 0x05
			flush()
			pending = &exDirItem{typ: typ, deleted: deleted, attrs: le16(d, 4)}
			// Create@8, modify@12, access@16 (DOS-style time/date pairs).
			pending.mtime = exfatDateTime(d[12:16])
			pending.ctime = exfatDateTime(d[8:12])
			if pending.attrs&0x10 != 0 {
				pending.isDir = true
			}
		case exEntryStream & 0x7F: // 0x40
			if pending == nil {
				continue
			}
			flags := d[1]
			pending.noChain = flags&0x02 != 0
			pending.validSize = int64(le64(d, 8))
			pending.size = int64(le64(d, 24))
			pending.clus = le32(d, 20)
		case exEntryName & 0x7F: // 0x41
			if pending == nil {
				continue
			}
			nameParts = append(nameParts, exfatUTF16(d[2:32]))
		case exEntryLabel & 0x7F: // 0x03
			flush()
			out = append(out, exDirItem{typ: typ, label: strings.TrimRight(exfatUTF16(d[2:32]), "\x00")})
		case exEntryBitmap & 0x7F, exEntryUpcase & 0x7F:
			flush()
		default:
			flush()
		}
	}
	flush()
	return out
}

func exfatUTF16(b []byte) string { return utf16Decode(b) }

// exfatDateTime decodes the 7-byte exFAT timestamp pair:
// double (2s) u16 @0, date u16 @2, time @4, tenths @6 — but the entry
// layout at d[8:16] is: Modified u16, Date u16, Accessed u16...
// The standard file time struct is 7 bytes: Time, Date, TimeTenths in a
// packed form; we accept d[8:] as: mtimeDouble(2), mtimeDate(2),
// atime(2), ctime...
func exfatDateTime(b []byte) time.Time {
	if len(b) < 4 {
		return time.Time{}
	}
	dtime := le16(b, 0)
	ddate := le16(b, 2)
	// Later fields (access/create) are at b[4:8] and b[8:12] in the full
	// 16-byte timestamp block; for listing purposes mtime suffices.
	year := 1980 + int(ddate>>9)
	mon := int(ddate >> 5 & 0x0F)
	day := int(ddate & 0x1F)
	hh := int(dtime >> 11)
	mm := int(dtime >> 5 & 0x3F)
	ss := int(dtime&0x1F) * 2
	if mon < 1 || mon > 12 || day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 61 {
		return time.Time{}
	}
	return time.Date(year, time.Month(mon), day, hh, mm, ss, 0, time.UTC)
}

// node resolves a path to its directory item.
func (e *exfatFS) resolve(comps []string) (exDirItem, error) {
	if len(comps) == 0 {
		return exDirItem{isDir: true, clus: e.rootClus}, nil
	}
	cur := exDirItem{isDir: true, clus: e.rootClus}
	for _, want := range comps {
		if !cur.isDir {
			return exDirItem{}, ErrNotFound
		}
		ents, err := e.readDirChain(cur.clus)
		if err != nil {
			return exDirItem{}, err
		}
		found := false
		for _, it := range ents {
			if it.deleted || it.label != "" || it.name == "" {
				continue
			}
			if strings.EqualFold(it.name, want) {
				cur = it
				found = true
				break
			}
		}
		if !found {
			return exDirItem{}, ErrNotFound
		}
	}
	return cur, nil
}

func (e *exfatFS) List(path string) ([]Entry, error) {
	comps := splitPath(path)
	node, err := e.resolve(comps)
	if err != nil {
		return nil, err
	}
	if !node.isDir {
		return nil, ErrNotDir
	}
	ents, err := e.readDirChain(node.clus)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, it := range ents {
		if it.deleted || it.label != "" || it.name == "" {
			continue
		}
		childPath := joinPath(append(append([]string{}, comps...), it.name))
		out = append(out, Entry{
			Name: it.name, Path: childPath, Dir: it.isDir,
			Size: it.size, Modified: it.mtime,
			Attributes: exfatAttrNames(it.attrs),
		})
	}
	return out, nil
}

func exfatAttrNames(a uint16) []string {
	var out []string
	if a&0x0001 != 0 {
		out = append(out, "readonly")
	}
	if a&0x0002 != 0 {
		out = append(out, "hidden")
	}
	if a&0x0004 != 0 {
		out = append(out, "system")
	}
	return out
}

func (e *exfatFS) Stat(path string) (Entry, error) {
	comps := splitPath(path)
	if len(comps) == 0 {
		return Entry{Name: "/", Path: "/", Dir: true}, nil
	}
	node, err := e.resolve(comps)
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		Name: node.name, Path: joinPath(comps), Dir: node.isDir,
		Size: node.size, Modified: node.mtime,
		Attributes: exfatAttrNames(node.attrs),
	}, nil
}

func (e *exfatFS) ReadAt(path string, off int64, p []byte) (int, error) {
	comps := splitPath(path)
	node, err := e.resolve(comps)
	if err != nil {
		return 0, err
	}
	if node.isDir {
		return 0, ErrIsDir
	}
	if off < 0 {
		return 0, fmt.Errorf("fs/exfat: negative offset")
	}
	if off >= node.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > node.size-off {
		want = int(node.size - off)
	}

	if node.noChain || node.clus == 0 {
		// Contiguous allocation (or empty file).
		if node.size == 0 {
			return 0, io.EOF
		}
		data, err := e.contigBytes(node.clus, node.size)
		if err != nil {
			return 0, err
		}
		// Bytes beyond validSize were never written: report zeros.
		for i := int64(0); i < int64(want); i++ {
			abs := off + i
			if node.validSize > 0 && abs >= node.validSize {
				p[i] = 0
			} else {
				p[i] = data[abs]
			}
		}
		if want < len(p) {
			return want, io.EOF
		}
		return want, nil
	}

	chain, err := e.chain(node.clus, e.maxChain())
	if err != nil {
		return 0, err
	}
	filled := 0
	for i := 0; i < len(chain) && filled < want; i++ {
		cStart := int64(i) * e.clus
		if off >= cStart+e.clus {
			continue
		}
		seek := off - cStart
		if seek < 0 {
			seek = 0
		}
		n := int(e.clus - seek)
		if n > want-filled {
			n = want - filled
		}
		buf := make([]byte, n)
		if err := e.r.readFull(buf, e.clusterOff(chain[i])+seek); err != nil {
			return filled, fmt.Errorf("fs/exfat: read: %w", err)
		}
		copy(p[filled:], buf)
		filled += n
		off += int64(n)
	}
	if filled < len(p) {
		return filled, io.EOF
	}
	return filled, nil
}
