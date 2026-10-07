package fs

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// FAT attribute bits.
const (
	fatAttrRO     = 0x01
	fatAttrHidden = 0x02
	fatAttrSystem = 0x04
	fatAttrVolume = 0x08
	fatAttrDir    = 0x10
	fatAttrArc    = 0x20
	fatAttrLFN    = 0x0F
)

type fatFS struct {
	r   rangeReader
	typ string // fat12, fat16, fat32

	bps   int // bytes per sector
	spc   int // sectors per cluster
	rsvd  int // reserved sectors
	fatSz int // sectors per FAT
	nFATs int

	rootEntCnt int // FAT12/16 root entries
	totSec     int

	fatStart  int64 // byte offset of FAT #0
	rootStart int64 // byte offset of FAT12/16 root dir
	rootBytes int64 // size of FAT12/16 root dir in bytes
	dataStart int64 // byte offset of cluster 2
	rootClus  uint32
	clusBytes int64

	label string

	mu       sync.Mutex
	fatCache map[uint32]uint32
}

func newFAT(r rangeReader, head []byte, _ int) (FS, error) {
	if len(head) < 512 || head[510] != 0x55 || head[511] != 0xAA {
		return nil, fmt.Errorf("fs/fat: missing boot signature")
	}
	f := &fatFS{r: r, fatCache: make(map[uint32]uint32)}
	f.bps = int(le16(head, 11))
	f.spc = int(head[13])
	f.rsvd = int(le16(head, 14))
	f.nFATs = int(head[16])
	f.rootEntCnt = int(le16(head, 17))
	fatSz16 := int(le16(head, 22))
	totSec16 := int(le16(head, 19))
	totSec32 := int(le32(head, 32))

	switch f.bps {
	case 512, 1024, 2048, 4096:
	default:
		return nil, fmt.Errorf("fs/fat: unsupported sector size %d", f.bps)
	}
	if f.spc == 0 || f.spc&(f.spc-1) != 0 || f.spc > 128 {
		return nil, fmt.Errorf("fs/fat: invalid sectors/cluster %d", f.spc)
	}
	if f.rsvd == 0 || f.nFATs == 0 || f.nFATs > 4 {
		return nil, fmt.Errorf("fs/fat: implausible geometry")
	}
	f.totSec = totSec16
	if f.totSec == 0 {
		f.totSec = totSec32
	}
	if f.totSec == 0 {
		f.totSec = int(r.size / int64(f.bps))
	}

	if fatSz16 != 0 {
		f.fatSz = fatSz16
		f.fatStart = int64(f.rsvd) * int64(f.bps)
		rootSecs := (int64(f.rootEntCnt)*32 + int64(f.bps) - 1) / int64(f.bps)
		f.rootStart = f.fatStart + int64(f.nFATs)*int64(f.fatSz)*int64(f.bps)
		f.rootBytes = rootSecs * int64(f.bps)
		f.dataStart = f.rootStart + f.rootBytes
	} else {
		f.fatSz = int(le32(head, 36))
		f.fatStart = int64(f.rsvd) * int64(f.bps)
		f.dataStart = f.fatStart + int64(f.nFATs)*int64(f.fatSz)*int64(f.bps)
		f.rootClus = le32(head, 44)
		if f.rootClus < 2 {
			return nil, fmt.Errorf("fs/fat: invalid root cluster %d", f.rootClus)
		}
	}
	if f.fatSz <= 0 {
		return nil, fmt.Errorf("fs/fat: zero-size FAT")
	}

	f.clusBytes = int64(f.spc) * int64(f.bps)
	dataSecs := int64(f.totSec) - f.dataStart/int64(f.bps)
	if dataSecs <= 0 {
		return nil, fmt.Errorf("fs/fat: no data area")
	}
	clusterCnt := uint32(dataSecs / int64(f.spc))

	switch {
	case clusterCnt < 4085:
		f.typ = "fat12"
	case clusterCnt < 65525:
		f.typ = "fat16"
	default:
		f.typ = "fat32"
	}

	labOff := 43
	if fatSz16 == 0 {
		labOff = 71
	}
	if labOff+11 <= len(head) {
		lab := strings.TrimSpace(string(head[labOff : labOff+11]))
		if lab != "" && lab != "NO NAME" {
			f.label = lab
		}
	}
	return f, nil
}

func (f *fatFS) Type() string     { return f.typ }
func (f *fatFS) TotalSize() int64 { return f.r.size }

func (f *fatFS) Label() string {
	if f.label != "" {
		return f.label
	}
	// Fall back to a root volume-label entry, if present.
	data, err := f.dirData(0)
	if err != nil {
		return ""
	}
	for _, e := range fatParseDir(data) {
		if e.attr == fatAttrVolume && !e.deleted {
			return strings.TrimSpace(e.shortName)
		}
	}
	return ""
}

// fatNext returns the FAT entry for cluster clus.
func (f *fatFS) fatNext(clus uint32) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.fatCache[clus]; ok {
		return v, nil
	}
	var off int64
	var n int
	switch f.typ {
	case "fat12":
		off = f.fatStart + int64(clus)*3/2
		n = 2
	case "fat16":
		off = f.fatStart + int64(clus)*2
		n = 2
	default:
		off = f.fatStart + int64(clus)*4
		n = 4
	}
	b := make([]byte, n)
	if err := f.r.readFull(b, off); err != nil {
		return 0, fmt.Errorf("fs/fat: read FAT entry %d: %w", clus, err)
	}
	var v uint32
	switch f.typ {
	case "fat12":
		v = uint32(le16(b, 0))
		if clus&1 == 1 {
			v >>= 4
		} else {
			v &= 0x0FFF
		}
	case "fat16":
		v = uint32(le16(b, 0))
	default:
		v = le32(b, 0) & 0x0FFFFFFF
	}
	f.fatCache[clus] = v
	return v, nil
}

// fatEOC reports whether v is an end-of-chain marker.
func (f *fatFS) fatEOC(v uint32) bool {
	switch f.typ {
	case "fat12":
		return v >= 0x0FF8
	case "fat16":
		return v >= 0xFFF0
	default:
		return v >= 0x0FFFFFF8
	}
}

// chain walks the cluster chain starting at clus. Guarded against loops
// and runaway chains.
func (f *fatFS) chain(clus uint32, limit int64) ([]uint32, error) {
	var out []uint32
	seen := make(map[uint32]bool)
	for clus >= 2 && !f.fatEOC(clus) && clus != 0x0FFFFFF7 {
		if seen[clus] {
			return out, fmt.Errorf("fs/fat: cluster loop at %d", clus)
		}
		seen[clus] = true
		out = append(out, clus)
		if int64(len(out)) > limit {
			return out, fmt.Errorf("fs/fat: chain too long (corrupt)")
		}
		next, err := f.fatNext(clus)
		if err != nil {
			return out, err
		}
		clus = next
	}
	return out, nil
}

// clusterOff returns the byte offset of cluster clus.
func (f *fatFS) clusterOff(clus uint32) int64 {
	return f.dataStart + int64(clus-2)*f.clusBytes
}

// maxChain bounds chain walks by the volume capacity.
func (f *fatFS) maxChain() int64 {
	return int64(f.r.size/f.clusBytes) + 8
}

// dirData reads the raw contents of a directory. firstClus==0 selects the
// fixed FAT12/16 root (or, for FAT32, the root cluster).
func (f *fatFS) dirData(firstClus uint32) ([]byte, error) {
	if firstClus == 0 && f.typ != "fat32" {
		buf := make([]byte, f.rootBytes)
		if err := f.r.readFull(buf, f.rootStart); err != nil {
			return nil, fmt.Errorf("fs/fat: read root dir: %w", err)
		}
		return buf, nil
	}
	if firstClus == 0 {
		firstClus = f.rootClus
	}
	chain, err := f.chain(firstClus, f.maxChain())
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, int64(len(chain))*f.clusBytes)
	tmp := make([]byte, f.clusBytes)
	for _, c := range chain {
		if err := f.r.readFull(tmp, f.clusterOff(c)); err != nil {
			return nil, fmt.Errorf("fs/fat: read dir cluster %d: %w", c, err)
		}
		buf = append(buf, tmp...)
	}
	return buf, nil
}

// fatDirEntry is a parsed short+LFN directory entry pair.
type fatDirEntry struct {
	shortName string
	lfn       string
	attr      byte
	clus      uint32
	size      int64
	mtime     time.Time
	ctime     time.Time
	deleted   bool
	// isDirRoot marks the synthetic node used for the volume root.
	isDirRoot bool
}

func fatParseDir(data []byte) []fatDirEntry {
	var out []fatDirEntry
	var lfnParts []string // appearance order: last fragment first
	lfnValid := false

	for off := 0; off+32 <= len(data); off += 32 {
		e := data[off:]
		first := e[0]
		if first == 0 {
			break // end of directory
		}
		attr := e[11]
		if attr == fatAttrLFN {
			if e[0]&0x40 != 0 { // last-on-disk marker: start fresh
				lfnParts = nil
				lfnValid = true
			}
			if !lfnValid {
				continue
			}
			var chunk strings.Builder
			chunk.WriteString(fatUTF16Field(e[1:11]))
			chunk.WriteString(fatUTF16Field(e[14:26]))
			chunk.WriteString(fatUTF16Field(e[28:32]))
			lfnParts = append(lfnParts, chunk.String())
			continue
		}
		if first == 0xE5 && attr == 0 {
			lfnParts, lfnValid = nil, false
			continue // fully freed slot
		}
		ent := fatDirEntry{
			shortName: fatShortName(e),
			attr:      attr,
			clus:      uint32(le16(e, 26)) | uint32(le16(e, 20))<<16,
			size:      int64(le32(e, 28)),
			mtime:     fatDateTime(e[22:24], e[24:26], nil),
			ctime:     fatDateTime(e[14:16], e[16:18], e[17:18]),
			deleted:   first == 0xE5,
		}
		if len(lfnParts) > 0 && lfnValid && ent.attr != fatAttrVolume {
			var sb strings.Builder
			for i := len(lfnParts) - 1; i >= 0; i-- {
				sb.WriteString(lfnParts[i])
			}
			if name := strings.TrimRight(sb.String(), "\x00"); name != "" {
				ent.lfn = name
			}
		}
		lfnParts, lfnValid = nil, false
		if ent.shortName == "" {
			continue
		}
		out = append(out, ent)
	}
	return out
}

func fatUTF16Field(b []byte) string {
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		c := rune(uint16(b[i]) | uint16(b[i+1])<<8)
		if c == 0 || c == 0xFFFF {
			break
		}
		sb.WriteRune(c)
	}
	return sb.String()
}

// fatShortName renders the classic 8.3 name from a raw entry.
func fatShortName(e []byte) string {
	base := string(e[0:8])
	ext := strings.TrimSpace(string(e[8:11]))
	if e[0] == 0xE5 {
		base = "?" + strings.TrimLeft(base[1:], " ")
	}
	if e[0] == 0x05 {
		base = "\xE5" + base[1:]
	}
	base = strings.TrimSpace(base)
	if base == "" {
		return ""
	}
	if ext != "" {
		return base + "." + ext
	}
	return base
}

// fatDateTime decodes a FAT time (2 bytes LE), date (2 bytes LE) and an
// optional tenths-of-second byte into a UTC instant.
func fatDateTime(tB, dB, tenths []byte) time.Time {
	if len(dB) < 2 || len(tB) < 2 {
		return time.Time{}
	}
	d := le16(dB, 0)
	t := le16(tB, 0)
	if d == 0 {
		return time.Time{}
	}
	year := 1980 + int(d>>9)
	month := int(d >> 5 & 0x0F)
	day := int(d & 0x1F)
	hour := int(t >> 11)
	min := int(t >> 5 & 0x3F)
	sec := int(t&0x1F) * 2
	if len(tenths) > 0 {
		sec += int(tenths[0]) / 100
	}
	if month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || min > 59 || sec > 61 {
		return time.Time{}
	}
	return time.Date(year, time.Month(month), day, hour, min, sec, 0, time.UTC)
}

func fatAttrNames(a byte) []string {
	var out []string
	if a&fatAttrRO != 0 {
		out = append(out, "readonly")
	}
	if a&fatAttrHidden != 0 {
		out = append(out, "hidden")
	}
	if a&fatAttrSystem != 0 {
		out = append(out, "system")
	}
	if a&fatAttrArc != 0 {
		out = append(out, "archive")
	}
	return out
}

// fatEntries converts raw directory data into entries with paths applied.
// Volume-label pseudo-entries are skipped; "." and ".." are skipped.
func (f *fatFS) fatEntries(data []byte, base []string) ([]Entry, []fatDirEntry) {
	raw := fatParseDir(data)
	ents := make([]Entry, 0, len(raw))
	nodes := make([]fatDirEntry, 0, len(raw))
	for _, e := range raw {
		if e.attr == fatAttrVolume {
			continue
		}
		name := e.lfn
		if name == "" {
			name = e.shortName
		}
		if name == "" || name == "." || name == ".." {
			continue
		}
		deleted := e.deleted
		if strings.HasPrefix(name, "?") {
			deleted = true
		}
		path := append(append([]string{}, base...), name)
		ent := Entry{
			Name:       name,
			Path:       joinPath(path),
			Dir:        e.attr&fatAttrDir != 0,
			Size:       e.size,
			Modified:   e.mtime,
			Created:    e.ctime,
			Deleted:    deleted,
			Attributes: fatAttrNames(e.attr),
		}
		if ent.Dir {
			ent.Size = 0
		}
		ents = append(ents, ent)
		nodes = append(nodes, e)
	}
	return ents, nodes
}

// resolve walks comps from the root and returns the matching node.
func (f *fatFS) resolve(comps []string) (fatDirEntry, error) {
	node := fatDirEntry{attr: fatAttrDir, isDirRoot: true}
	if len(comps) == 0 {
		return node, nil
	}
	var cur []string
	for _, want := range comps {
		if !node.isDirRoot && node.attr&fatAttrDir == 0 {
			return fatDirEntry{}, ErrNotFound
		}
		data, err := f.dirData(node.firstClus())
		if err != nil {
			return fatDirEntry{}, err
		}
		ents, raw := f.fatEntries(data, cur)
		found := false
		for i, e := range ents {
			if strings.EqualFold(e.Name, want) {
				node = raw[i]
				cur = append(cur, e.Name)
				found = true
				break
			}
		}
		if !found {
			return fatDirEntry{}, ErrNotFound
		}
	}
	return node, nil
}

func (n fatDirEntry) firstClus() uint32 {
	if n.isDirRoot {
		return 0 // dirData maps 0 to fixed root / FAT32 root cluster
	}
	return n.clus
}

func (f *fatFS) List(path string) ([]Entry, error) {
	comps := splitPath(path)
	node, err := f.resolve(comps)
	if err != nil {
		return nil, err
	}
	if !node.isDirRoot && node.attr&fatAttrDir == 0 {
		return nil, ErrNotDir
	}
	data, err := f.dirData(node.firstClus())
	if err != nil {
		return nil, err
	}
	ents, _ := f.fatEntries(data, comps)
	return ents, nil
}

func (f *fatFS) Stat(path string) (Entry, error) {
	comps := splitPath(path)
	node, err := f.resolve(comps)
	if err != nil {
		return Entry{}, err
	}
	if len(comps) == 0 {
		return Entry{Name: "/", Path: "/", Dir: true}, nil
	}
	name := comps[len(comps)-1]
	parent := comps[:len(comps)-1]
	// Recover full metadata (times, attributes, LFN) from the parent
	// listing; resolve() already found the node but keeps less detail.
	if pdata, perr := f.dirData(parentFirstClus(f, parent)); perr == nil {
		ents, _ := f.fatEntries(pdata, parent)
		for _, e := range ents {
			if strings.EqualFold(e.Name, name) {
				return e, nil
			}
		}
	}
	return Entry{
		Name: name, Path: joinPath(comps),
		Dir:  node.isDirRoot || node.attr&fatAttrDir != 0,
		Size: node.size, Modified: node.mtime, Created: node.ctime,
		Deleted: node.deleted, Attributes: fatAttrNames(node.attr),
	}, nil
}

func parentFirstClus(f *fatFS, parent []string) uint32 {
	if len(parent) == 0 {
		return 0 // root
	}
	n, err := f.resolve(parent)
	if err != nil {
		return 0
	}
	return n.firstClus()
}

func (f *fatFS) ReadAt(path string, off int64, p []byte) (int, error) {
	comps := splitPath(path)
	node, err := f.resolve(comps)
	if err != nil {
		return 0, err
	}
	if node.isDirRoot || node.attr&fatAttrDir != 0 {
		return 0, ErrIsDir
	}
	if off < 0 {
		return 0, fmt.Errorf("fs/fat: negative offset")
	}
	if off >= node.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > node.size-off {
		want = int(node.size - off)
	}
	if node.clus < 2 {
		if node.size == 0 {
			return 0, io.EOF
		}
		return 0, fmt.Errorf("fs/fat: file %q has data but no clusters", path)
	}
	chain, err := f.chain(node.clus, f.maxChain())
	if err != nil {
		return 0, err
	}
	filled := 0
	for i := 0; i < len(chain) && filled < want; i++ {
		cStart := int64(i) * f.clusBytes
		if off >= cStart+f.clusBytes {
			continue
		}
		seek := off - cStart
		if seek < 0 {
			seek = 0
		}
		n := int(f.clusBytes - seek)
		if n > want-filled {
			n = want - filled
		}
		buf := make([]byte, n)
		if err := f.r.readFull(buf, f.clusterOff(chain[i])+seek); err != nil {
			return filled, fmt.Errorf("fs/fat: read cluster %d: %w", chain[i], err)
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
