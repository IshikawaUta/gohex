package fs

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// ISO 9660 (plus Rock Ridge "NM" names and Joliet UCS-2 names) reader.
type isoFS struct {
	r      rangeReader
	block  int64 // logical block size
	root   isoDir
	joliet bool
	label  string
}

// isoDir is a decoded directory record (34+ bytes).
type isoDir struct {
	extent int64 // byte offset of directory data
	size   int64
}

func newISO(r rangeReader) (FS, error) {
	if r.size < 0x8000+2048 {
		return nil, fmt.Errorf("fs/iso: too small for ISO9660")
	}
	// Scan volume descriptors starting at sector 16 (0x8000).
	var pvd, jolietSVD []byte
	for off := int64(0x8000); off+2048 <= r.size; off += 2048 {
		buf := make([]byte, 2048)
		if err := r.readFull(buf, off); err != nil {
			return nil, fmt.Errorf("fs/iso: read volume descriptor: %w", err)
		}
		if string(buf[1:6]) != "CD001" {
			return nil, fmt.Errorf("fs/iso: bad volume descriptor signature")
		}
		switch buf[0] {
		case 1:
			if pvd == nil {
				pvd = buf
			}
		case 2:
			// Joliet supplementary: UCS-2 escape sequence %/@, %/C, %/E.
			if jolietSVD == nil && buf[88] == '%' && buf[89] == '/' &&
				(buf[90] == '@' || buf[90] == 'C' || buf[90] == 'E') {
				jolietSVD = buf
			}
		case 255:
			goto done
		}
	}
done:
	chosen := pvd
	isJoliet := false
	if jolietSVD != nil {
		chosen, isJoliet = jolietSVD, true
	}
	if chosen == nil {
		return nil, fmt.Errorf("fs/iso: no primary volume descriptor")
	}

	// Logical block size lives at PVD offset 128 (both-endian 16-bit).
	e := &isoFS{r: r, block: int64(le16(chosen, 128)), joliet: isJoliet}
	if e.block < 2048 || e.block&(e.block-1) != 0 {
		return nil, fmt.Errorf("fs/iso: invalid block size %d", e.block)
	}
	root, err := isoParseRecord(chosen[156:], e.block)
	if err != nil {
		return nil, fmt.Errorf("fs/iso: root record: %w", err)
	}
	e.root = root
	e.label = isoVolumeID(chosen, isJoliet)
	return e, nil
}

func (e *isoFS) Type() string     { return "iso9660" }
func (e *isoFS) TotalSize() int64 { return e.r.size }

// isoVolumeID decodes the volume identifier (offset 40..72) of the
// descriptor that owns the names, UCS-2 for Joliet, ASCII otherwise.
func isoVolumeID(desc []byte, joliet bool) string {
	if joliet {
		var sb strings.Builder
		for i := 40; i+1 < 72; i += 2 {
			c := rune(uint16(desc[i])<<8 | uint16(desc[i+1]))
			if c == 0 {
				break
			}
			sb.WriteRune(c)
		}
		return strings.TrimRight(sb.String(), " ")
	}
	return strings.TrimSpace(string(desc[40:72]))
}

func (e *isoFS) Label() string { return e.label }

// isoParseRecord decodes a 7+ directory record.
func isoParseRecord(rec []byte, block int64) (isoDir, error) {
	if len(rec) < 34 || rec[0] < 34 {
		return isoDir{}, fmt.Errorf("short record")
	}
	extent := int64(le32(rec, 2)) * block
	size := int64(le32(rec, 10))
	return isoDir{extent: extent, size: size}, nil
}

// isoEntry is a decoded directory item.
type isoEntry struct {
	name    string
	rr      string // Rock Ridge NM name, if any
	dir     bool
	size    int64
	mtime   time.Time
	extent  int64
	extSize int64
}

func isoDateTime(b []byte) time.Time {
	if len(b) < 7 {
		return time.Time{}
	}
	year := 1900 + int(b[0])
	mon := int(b[1])
	day := int(b[2])
	hh := int(b[3])
	mm := int(b[4])
	ss := int(b[5])
	if mon < 1 || mon > 12 || day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 60 {
		return time.Time{}
	}
	return time.Date(year, time.Month(mon), day, hh, mm, ss, 0, time.UTC)
}

// parseDir reads a directory and returns its items. Names come from
// Joliet/UCS-2 fields when the volume is Joliet, refined by Rock Ridge
// "NM" entries when present.
func (e *isoFS) parseDir(d isoDir) ([]isoEntry, error) {
	if d.size == 0 || d.size > 64<<20 {
		return nil, nil
	}
	buf := make([]byte, d.size)
	if _, err := e.r.ReadAt(buf, d.extent); err != nil && err != io.EOF {
		return nil, fmt.Errorf("fs/iso: read dir: %w", err)
	}
	var out []isoEntry
	for off := 0; off+34 <= len(buf); {
		l := int(buf[off])
		if l == 0 {
			// Skip to the next sector boundary.
			next := (off/int(e.block) + 1) * int(e.block)
			if next <= off {
				break
			}
			off = next
			continue
		}
		if off+l > len(buf) {
			break
		}
		rec := buf[off : off+l]
		ent, err := e.parseItem(rec)
		if err != nil {
			off += l
			continue
		}
		if ent.name != "" && ent.name != "." && ent.name != ".." {
			out = append(out, ent)
		}
		off += l
	}
	return out, nil
}

func (e *isoFS) parseItem(rec []byte) (isoEntry, error) {
	ent := isoEntry{
		dir:     rec[25]&0x02 != 0,
		size:    int64(le32(rec, 10)),
		mtime:   isoDateTime(rec[18:25]),
		extent:  int64(le32(rec, 2)) * e.block,
		extSize: int64(le32(rec, 10)),
	}
	nameLen := int(rec[32])
	nameBytes := rec[33 : 33+nameLen]
	pad := 0
	if nameLen%2 == 0 {
		pad = 1 // pad field after even-length names
	}
	sysArea := rec[33+nameLen+pad:]

	if e.joliet {
		// Joliet names are UCS-2 big-endian.
		var sb strings.Builder
		for i := 0; i+1 < len(nameBytes); i += 2 {
			c := rune(uint16(nameBytes[i])<<8 | uint16(nameBytes[i+1]))
			if c == 0 {
				break
			}
			sb.WriteRune(c)
		}
		ent.name = sb.String()
	} else {
		ent.name = isoPlainName(string(nameBytes))
	}
	// Rock Ridge SUSP walk for the real name.
	if rr := rrName(sysArea); rr != "" {
		ent.rr = rr
	}
	if ent.rr != "" {
		ent.name = ent.rr
	}
	return ent, nil
}

// isoPlainName strips ISO version suffixes ("FILE.TXT;1").
func isoPlainName(s string) string {
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = s[:i]
	}
	return s
}

// rrName scans SUSP/RR entries for a Rock Ridge alternate name ("NM").
// Only the inline system-use area is walked; CE continuation areas are
// not followed (rare for the directories we list). The SP marker is only
// mandated for the root "." record; other records start directly with
// their SUSP entries (PX, NM, ...), so SP is skipped when present.
func rrName(sys []byte) string {
	off := 0
	if len(sys) >= 7 && string(sys[0:2]) == "SP" {
		off = int(sys[2]) // length of the SP entry
	}
	for off+4 <= len(sys) {
		sig := string(sys[off : off+2])
		elen := int(sys[off+2])
		if elen < 4 || off+elen > len(sys) {
			break
		}
		if sig == "NM" && elen > 5 {
			return string(sys[off+5 : off+elen])
		}
		if sig == "ST" {
			break
		}
		off += elen
	}
	return ""
}

// resolve walks comps from the root directory.
func (e *isoFS) resolve(comps []string) (isoDir, isoEntry, error) {
	cur := e.root
	var curEnt isoEntry
	for _, want := range comps {
		ents, err := e.parseDir(cur)
		if err != nil {
			return isoDir{}, isoEntry{}, err
		}
		found := false
		for _, de := range ents {
			if de.name == want || strings.EqualFold(de.name, want) {
				cur = isoDir{extent: de.extent, size: de.extSize}
				curEnt = de
				found = true
				break
			}
		}
		if !found {
			return isoDir{}, isoEntry{}, ErrNotFound
		}
	}
	return cur, curEnt, nil
}

func (e *isoFS) List(path string) ([]Entry, error) {
	comps := splitPath(path)
	d, de, err := e.resolve(comps)
	if err != nil {
		return nil, err
	}
	if len(comps) > 0 && !de.dir {
		return nil, ErrNotDir
	}
	ents, err := e.parseDir(d)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(ents))
	for _, de := range ents {
		childPath := joinPath(append(append([]string{}, comps...), de.name))
		out = append(out, Entry{
			Name: de.name, Path: childPath, Dir: de.dir,
			Size: de.size, Modified: de.mtime,
		})
	}
	return out, nil
}

func (e *isoFS) Stat(path string) (Entry, error) {
	comps := splitPath(path)
	if len(comps) == 0 {
		return Entry{Name: "/", Path: "/", Dir: true}, nil
	}
	d, de, err := e.resolve(comps)
	if err != nil {
		return Entry{}, err
	}
	_ = d
	return Entry{
		Name: de.name, Path: joinPath(comps), Dir: de.dir,
		Size: de.size, Modified: de.mtime,
	}, nil
}

func (e *isoFS) ReadAt(path string, off int64, p []byte) (int, error) {
	comps := splitPath(path)
	d, de, err := e.resolve(comps)
	if err != nil {
		return 0, err
	}
	if de.dir {
		return 0, ErrIsDir
	}
	if off < 0 {
		return 0, fmt.Errorf("fs/iso: negative offset")
	}
	if off >= de.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > de.size-off {
		want = int(de.size - off)
	}
	if err := e.r.readFull(p[:want], d.extent+off); err != nil {
		return 0, fmt.Errorf("fs/iso: read data: %w", err)
	}
	if want < len(p) {
		return want, io.EOF
	}
	return want, nil
}
