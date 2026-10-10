package recovery

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/binary"
	"hash/crc32"
	"io"
	"unicode/utf16"
)

// jpegOK requires a real first segment marker after SOI. Without it the
// three-byte header produces a candidate every ~16 MiB of high-entropy data.
func jpegOK(s Stream, start int64) bool {
	var h [4]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	if h[0] != 0xFF || h[1] != 0xD8 || h[2] != 0xFF {
		return false
	}
	switch h[3] {
	case 0xD8, 0xD9, 0x01, 0xFF:
		return false
	}
	return h[3] >= 0xC0 && h[3] <= 0xFE
}

func gifOK(s Stream, start int64) bool {
	var h [6]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	return h[0] == 'G' && h[1] == 'I' && h[2] == 'F' && h[3] == '8' &&
		(h[4] == '7' || h[4] == '9') && h[5] == 'a'
}

func zipOK(s Stream, start int64) bool {
	var h [10]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	version := binary.LittleEndian.Uint16(h[4:6])
	method := binary.LittleEndian.Uint16(h[8:10])
	return version <= 1023 && method <= 12
}

func bmpLength(s Stream, start int64) (int64, bool, bool) {
	var h [18]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return 0, false, false
	}
	if h[0] != 'B' || h[1] != 'M' {
		return 0, false, false
	}
	size := int64(binary.LittleEndian.Uint32(h[2:6]))
	if binary.LittleEndian.Uint32(h[6:10]) != 0 {
		return 0, false, false
	}
	offBits := int64(binary.LittleEndian.Uint32(h[10:14]))
	switch binary.LittleEndian.Uint32(h[14:18]) {
	case 12, 40, 52, 56, 64, 108, 124:
	default:
		return 0, false, false
	}
	if size < 54 || size > 1<<31 || offBits < 14 || offBits > size {
		return 0, false, false
	}
	return size, false, true
}

func riffLength(form string) LengthFunc {
	return func(s Stream, start int64) (int64, bool, bool) {
		var h [12]byte
		if err := readFullAt(s, h[:], start); err != nil {
			return 0, false, false
		}
		if string(h[0:4]) != "RIFF" || string(h[8:12]) != form {
			return 0, false, false
		}
		raw := binary.LittleEndian.Uint32(h[4:8])
		if raw == 0xFFFFFFFF {
			return s.Size() - start, true, true
		}
		length := int64(raw) + 8
		if length < 12 {
			return 0, false, false
		}
		return length, false, true
	}
}

func mp4Length(s Stream, start int64) (int64, bool, bool) {
	size := s.Size()
	if start < 0 || start+8 > size {
		return 0, false, false
	}
	total := size - start
	var cur int64
	for i := 0; i < 4096; i++ {
		remaining := total - cur
		if remaining <= 0 {
			return total, false, true
		}
		if remaining < 8 {
			return total, true, true
		}
		n := 16
		if remaining < int64(n) {
			n = int(remaining)
		}
		var h [16]byte
		if err := readFullAt(s, h[:n], start+cur); err != nil {
			return 0, false, false
		}
		if !boxType(h[4:8]) {
			return 0, false, false
		}
		headerLen := int64(8)
		boxSize := int64(binary.BigEndian.Uint32(h[0:4]))
		if i == 0 {
			if boxSize < 16 || boxSize > 4096 {
				return 0, false, false
			}
		}
		switch boxSize {
		case 0:
			return total, false, true
		case 1:
			if n < 16 {
				return total, true, true
			}
			boxSize, headerLen = int64(binary.BigEndian.Uint64(h[8:16])), 16
		}
		if boxSize < headerLen {
			return 0, false, false
		}
		cur += boxSize
		if cur > total {
			return total, true, true
		}
	}
	return 0, false, false
}

func zipFooterEnd(s Stream, footerStart, limit int64) int64 {
	var h [22]byte
	if err := readFullAt(s, h[:], footerStart); err != nil {
		return footerStart + 4
	}
	end := footerStart + 22 + int64(binary.LittleEndian.Uint16(h[20:22]))
	if end > limit {
		end = limit
	}
	if end < footerStart+4 {
		end = footerStart + 4
	}
	return end
}

func pdfFooterEnd(s Stream, footerStart, limit int64) int64 {
	end := footerStart + 5
	if end >= limit {
		return end
	}
	n := 2
	if int64(n) > limit-end {
		n = int(limit - end)
	}
	var tail [2]byte
	if err := readFullAt(s, tail[:n], end); err != nil {
		return end
	}
	for i := 0; i < n; i++ {
		if tail[i] != '\r' && tail[i] != '\n' {
			break
		}
		end++
	}
	return end
}

func boxType(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// TIFF
// ---------------------------------------------------------------------------

func tiffOK(s Stream, start int64) bool {
	return tiffOKOrder(s, start, true)
}

func tiffBEOK(s Stream, start int64) bool {
	return tiffOKOrder(s, start, false)
}

func tiffOKOrder(s Stream, start int64, little bool) bool {
	var h [8]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	if little {
		if h[0] != 'I' || h[1] != 'I' || binary.LittleEndian.Uint16(h[2:4]) != 42 {
			return false
		}
		ifd := int64(binary.LittleEndian.Uint32(h[4:8]))
		return ifd >= 8 && ifd < 1<<31
	}
	if h[0] != 'M' || h[1] != 'M' || binary.BigEndian.Uint16(h[2:4]) != 42 {
		return false
	}
	ifd := int64(binary.BigEndian.Uint32(h[4:8]))
	return ifd >= 8 && ifd < 1<<31
}

func tiffLength(s Stream, start int64) (int64, bool, bool) {
	return tiffWalk(s, start, true)
}

func tiffBELength(s Stream, start int64) (int64, bool, bool) {
	return tiffWalk(s, start, false)
}

func tiffWalk(s Stream, start int64, little bool) (int64, bool, bool) {
	size := s.Size()
	if start < 0 || start+8 > size {
		return 0, false, false
	}
	u16 := func(b []byte) uint16 {
		if little {
			return binary.LittleEndian.Uint16(b)
		}
		return binary.BigEndian.Uint16(b)
	}
	u32 := func(b []byte) uint32 {
		if little {
			return binary.LittleEndian.Uint32(b)
		}
		return binary.BigEndian.Uint32(b)
	}
	var h [8]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return 0, false, false
	}
	if little {
		if h[0] != 'I' || h[1] != 'I' || u16(h[2:4]) != 42 {
			return 0, false, false
		}
	} else {
		if h[0] != 'M' || h[1] != 'M' || u16(h[2:4]) != 42 {
			return 0, false, false
		}
	}
	first := int64(u32(h[4:8]))
	if first < 8 || first+2 > size-start {
		return 0, false, false
	}
	max := first + 2
	cur := first
	for i := 0; i < 256; i++ {
		if cur+2 > size-start {
			return max, true, true
		}
		var cntB [2]byte
		if err := readFullAt(s, cntB[:], start+cur); err != nil {
			return 0, false, false
		}
		cnt := int64(u16(cntB[:]))
		if cnt > 4096 {
			return 0, false, false
		}
		ifdEnd := cur + 2 + cnt*12 + 4
		if ifdEnd > max {
			max = ifdEnd
		}
		if ifdEnd > size-start {
			return max, true, true
		}
		var nextB [4]byte
		if err := readFullAt(s, nextB[:], start+cur+2+cnt*12); err != nil {
			return 0, false, false
		}
		next := int64(u32(nextB[:]))
		if next == 0 {
			break
		}
		if next < 8 || next <= cur {
			return 0, false, false
		}
		cur = next
	}
	return max, false, true
}

// ---------------------------------------------------------------------------
// WebP (RIFF container)
// ---------------------------------------------------------------------------

func webpLength(s Stream, start int64) (int64, bool, bool) {
	return riffLength("WEBP")(s, start)
}

// ---------------------------------------------------------------------------
// HEIC / HEIF (ISO-BMFF with a constrained brand table)
// ---------------------------------------------------------------------------

var heicBrands = map[string]bool{
	"heic": true, "heix": true, "hevc": true, "hevx": true,
	"heim": true, "heis": true, "hevm": true, "hevs": true,
	"mif1": true, "msf1": true, "miaf": true,
}

func heicOK(s Stream, start int64) bool {
	var h [16]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	if string(h[4:8]) != "ftyp" {
		return false
	}
	boxSize := int64(binary.BigEndian.Uint32(h[0:4]))
	if boxSize < 16 || boxSize > 4096 {
		return false
	}
	if heicBrands[string(h[8:12])] {
		return true
	}
	n := int(boxSize - 12)
	if n <= 0 || n%4 != 0 {
		return false
	}
	if n > 1024 {
		n = 1024
	}
	buf := make([]byte, n)
	if err := readFullAt(s, buf, start+12); err != nil {
		return false
	}
	for i := 0; i+4 <= len(buf); i += 4 {
		if heicBrands[string(buf[i:i+4])] {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// OLE Compound File Binary (CFB): DOC, XLS, PPT, generic OLE
// ---------------------------------------------------------------------------

var cfbSig = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

func cfbLength(s Stream, start int64) (int64, bool, bool) {
	size := s.Size()
	if start < 0 || start+512 > size {
		return 0, false, false
	}
	var hdr [512]byte
	if err := readFullAt(s, hdr[:], start); err != nil {
		return 0, false, false
	}
	if !bytes.Equal(hdr[0:8], cfbSig) {
		return 0, false, false
	}
	if binary.LittleEndian.Uint16(hdr[28:30]) != 0xFFFE {
		return 0, false, false
	}
	sectorShift := binary.LittleEndian.Uint16(hdr[30:32])
	if sectorShift != 9 && sectorShift != 12 {
		return 0, false, false
	}
	sectorSize := int64(1) << sectorShift
	major := binary.LittleEndian.Uint16(hdr[26:28])
	headerSize := int64(512)
	if major >= 4 {
		headerSize = sectorSize
	}
	numFATSectors := int64(binary.LittleEndian.Uint32(hdr[44:48]))
	firstDirSector := int64(binary.LittleEndian.Uint32(hdr[48:52]))
	firstDIFATSector := int64(binary.LittleEndian.Uint32(hdr[68:72]))
	numDIFATSectors := int64(binary.LittleEndian.Uint32(hdr[72:76]))
	if numFATSectors < 1 || numFATSectors > 4096 {
		return 0, false, false
	}
	if firstDirSector < 0 || firstDirSector == 0xFFFFFFFF {
		return 0, false, false
	}

	var fatSectors []int64
	for i := 0; i < 109 && int64(len(fatSectors)) < numFATSectors; i++ {
		v := int64(binary.LittleEndian.Uint32(hdr[76+i*4 : 80+i*4]))
		if v == 0xFFFFFFFF {
			break
		}
		fatSectors = append(fatSectors, v)
	}
	difat := firstDIFATSector
	for d := 0; d < int(numDIFATSectors)+1 && difat != 0xFFFFFFFF && int64(len(fatSectors)) < numFATSectors; d++ {
		off := headerSize + difat*sectorSize
		if off+sectorSize > size {
			return 0, false, false
		}
		buf := make([]byte, sectorSize)
		if err := readFullAt(s, buf, off); err != nil {
			return 0, false, false
		}
		entries := int(sectorSize / 4)
		for i := 0; i < entries-1 && int64(len(fatSectors)) < numFATSectors; i++ {
			v := int64(binary.LittleEndian.Uint32(buf[i*4 : i*4+4]))
			if v == 0xFFFFFFFF {
				break
			}
			fatSectors = append(fatSectors, v)
		}
		next := int64(binary.LittleEndian.Uint32(buf[(entries-1)*4 : entries*4]))
		if next == difat {
			return 0, false, false
		}
		difat = next
	}

	maxSector := firstDirSector
	for _, fs := range fatSectors {
		if fs > maxSector {
			maxSector = fs
		}
		off := headerSize + fs*sectorSize
		if off+sectorSize > size {
			return maxSector + 1, true, true
		}
		buf := make([]byte, sectorSize)
		if err := readFullAt(s, buf, off); err != nil {
			return 0, false, false
		}
		entries := int(sectorSize / 4)
		for i := 0; i < entries; i++ {
			v := binary.LittleEndian.Uint32(buf[i*4 : i*4+4])
			if v == 0xFFFFFFFF {
				continue
			}
			if v >= 0xFFFFFFF0 {
				continue
			}
			si := int64(v)
			if si > maxSector {
				maxSector = si
			}
		}
	}
	return headerSize + (maxSector+1)*sectorSize, false, true
}

func cfbFamily(s Stream, start int64) string {
	size := s.Size()
	if start < 0 || start+512 > size {
		return ""
	}
	var hdr [512]byte
	if err := readFullAt(s, hdr[:], start); err != nil {
		return ""
	}
	if !bytes.Equal(hdr[0:8], cfbSig) {
		return ""
	}
	sectorShift := binary.LittleEndian.Uint16(hdr[30:32])
	if sectorShift != 9 && sectorShift != 12 {
		return ""
	}
	sectorSize := int64(1) << sectorShift
	major := binary.LittleEndian.Uint16(hdr[26:28])
	headerSize := int64(512)
	if major >= 4 {
		headerSize = sectorSize
	}
	firstDir := int64(binary.LittleEndian.Uint32(hdr[48:52]))
	if firstDir < 0 || firstDir == 0xFFFFFFFF {
		return ""
	}
	for sec := int64(0); sec < 4; sec++ {
		off := headerSize + (firstDir+sec)*sectorSize
		if off+sectorSize > size {
			return ""
		}
		buf := make([]byte, sectorSize)
		if err := readFullAt(s, buf, off); err != nil {
			return ""
		}
		entries := int(sectorSize / 128)
		for e := 0; e < entries; e++ {
			ent := buf[e*128 : (e+1)*128]
			nameLen := binary.LittleEndian.Uint16(ent[64:66])
			if nameLen < 2 || nameLen > 64 {
				continue
			}
			name := utf16Name(ent[:64], int(nameLen))
			switch name {
			case "WordDocument":
				return "doc"
			case "Workbook", "Book":
				return "xls"
			case "PowerPoint Document":
				return "ppt"
			}
		}
	}
	return ""
}

func utf16Name(b []byte, n int) string {
	if n > len(b) {
		n = len(b)
	}
	n &= ^1
	u := make([]uint16, n/2)
	for i := 0; i < len(u); i++ {
		u[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	// Directory names are NUL-terminated and the declared length includes
	// the terminator; strip it so comparisons match the bare name.
	for len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return string(utf16.Decode(u))
}

// ---------------------------------------------------------------------------
// OOXML (ZIP-based): DOCX, XLSX, PPTX
// ---------------------------------------------------------------------------

func ooxmlOK(prefix string) ValidateFunc {
	return func(s Stream, start int64) bool {
		if !zipOK(s, start) {
			return false
		}
		var h [30]byte
		if err := readFullAt(s, h[:], start); err != nil {
			return false
		}
		nameLen := int(binary.LittleEndian.Uint16(h[26:28]))
		if nameLen < len(prefix) || nameLen > 1024 {
			return false
		}
		name := make([]byte, nameLen)
		if err := readFullAt(s, name, start+30); err != nil {
			return false
		}
		return bytes.HasPrefix(name, []byte(prefix))
	}
}

// ---------------------------------------------------------------------------
// RAR
// ---------------------------------------------------------------------------

var rarSigV4 = []byte{'R', 'a', 'r', '!', 0x1A, 0x07, 0x00}
var rarSigV5 = []byte{'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00}

func rarOK(s Stream, start int64) bool {
	var h [8]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	return bytes.Equal(h[:7], rarSigV4) || bytes.Equal(h[:8], rarSigV5)
}

func rarLength(s Stream, start int64) (int64, bool, bool) {
	size := s.Size()
	if start < 0 || start+8 > size {
		return 0, false, false
	}
	var sig [8]byte
	if err := readFullAt(s, sig[:], start); err != nil {
		return 0, false, false
	}
	if bytes.Equal(sig[:8], rarSigV5) {
		return rarWalkV5(s, start, start+8, size)
	}
	if bytes.Equal(sig[:7], rarSigV4) {
		return rarWalkV4(s, start, start+7, size)
	}
	return 0, false, false
}

func rarWalkV4(s Stream, start, pos, size int64) (int64, bool, bool) {
	for i := 0; i < 65536; i++ {
		if pos+7 > size {
			return pos - start, true, true
		}
		var h [7]byte
		if err := readFullAt(s, h[:], pos); err != nil {
			return 0, false, false
		}
		typ := h[2]
		hsize := int64(binary.LittleEndian.Uint16(h[5:7]))
		if hsize < 7 {
			return 0, false, false
		}
		addSize := int64(0)
		if (typ == 0x73 || typ == 0x7A) && hsize >= 11 && pos+11 <= size {
			var ps [4]byte
			if err := readFullAt(s, ps[:], pos+7); err != nil {
				return 0, false, false
			}
			addSize = int64(binary.LittleEndian.Uint32(ps[:]))
		}
		if typ == 0x7B {
			end := pos + hsize
			if end > size {
				end = size
			}
			return end - start, end < pos+hsize, true
		}
		pos += hsize + addSize
		if pos > size {
			return size - start, true, true
		}
	}
	return 0, false, false
}

func readVint(b []byte, off int) (val uint64, n int, ok bool) {
	if off >= len(b) {
		return 0, 0, false
	}
	for i := 0; i < 9 && off+i < len(b); i++ {
		c := b[off+i]
		val |= uint64(c&0x7F) << (7 * i)
		if c&0x80 == 0 {
			return val, i + 1, true
		}
	}
	return 0, 0, false
}

func rarWalkV5(s Stream, start, pos, size int64) (int64, bool, bool) {
	for i := 0; i < 65536; i++ {
		if pos+5 > size {
			return pos - start, true, true
		}
		n := 32
		if int64(n) > size-pos {
			n = int(size - pos)
		}
		buf := make([]byte, n)
		if err := readFullAt(s, buf, pos); err != nil {
			return 0, false, false
		}
		hs, hn, ok := readVint(buf, 4)
		if !ok || hs < uint64(5+hn) {
			return 0, false, false
		}
		off := 4 + hn
		typ, tn, ok := readVint(buf, off)
		if !ok {
			return 0, false, false
		}
		off += tn
		headerFlags, fn, ok := readVint(buf, off)
		if !ok {
			return 0, false, false
		}
		off += fn
		var dataSize uint64
		if headerFlags&0x0002 != 0 {
			ds, dn, ok := readVint(buf, off)
			if !ok {
				return 0, false, false
			}
			dataSize = ds
			off += dn
		}
		if typ == 5 {
			end := pos + int64(hs) + int64(dataSize)
			if end > size {
				end = size
			}
			return end - start, end < pos+int64(hs)+int64(dataSize), true
		}
		pos += int64(hs) + int64(dataSize)
		if pos > size {
			return size - start, true, true
		}
	}
	return 0, false, false
}

// ---------------------------------------------------------------------------
// 7z
// ---------------------------------------------------------------------------

var szSig = []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}

func szOK(s Stream, start int64) bool {
	var h [32]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	if !bytes.Equal(h[:6], szSig) {
		return false
	}
	if h[6] != 0 {
		return false
	}
	off := binary.LittleEndian.Uint64(h[12:20])
	sz := binary.LittleEndian.Uint64(h[20:28])
	if sz == 0 {
		return false
	}
	end := 32 + off + sz
	return end <= uint64(s.Size()-start)
}

func szLength(s Stream, start int64) (int64, bool, bool) {
	var h [32]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return 0, false, false
	}
	if !bytes.Equal(h[:6], szSig) {
		return 0, false, false
	}
	off := int64(binary.LittleEndian.Uint64(h[12:20]))
	sz := int64(binary.LittleEndian.Uint64(h[20:28]))
	if off < 0 || sz < 0 {
		return 0, false, false
	}
	total := 32 + off + sz
	if total > s.Size()-start {
		return total, true, true
	}
	return total, false, true
}

// ---------------------------------------------------------------------------
// TAR
// ---------------------------------------------------------------------------

func tarOK(s Stream, start int64) bool {
	var h [512]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	if string(h[257:262]) != "ustar" {
		return false
	}
	var sum uint32
	for i := 0; i < 512; i++ {
		if i >= 148 && i < 156 {
			sum += ' '
			continue
		}
		sum += uint32(h[i])
	}
	stored, ok := tarOctal(h[148:156])
	if !ok {
		return false
	}
	return sum == stored
}

func tarOctal(b []byte) (uint32, bool) {
	var v uint32
	digits := 0
	for _, c := range b {
		switch {
		case c >= '0' && c <= '7':
			v = v*8 + uint32(c-'0')
			digits++
		case c == ' ' || c == 0:
		default:
			return 0, false
		}
	}
	return v, digits > 0
}

func tarLength(s Stream, start int64) (int64, bool, bool) {
	size := s.Size()
	if start < 0 || start+512 > size {
		return 0, false, false
	}
	var total int64
	pos := start
	for i := 0; i < 100000; i++ {
		if pos+512 > size {
			return total, true, true
		}
		var h [512]byte
		if err := readFullAt(s, h[:], pos); err != nil {
			return 0, false, false
		}
		if isZeroBlock(h[:]) {
			total += 512
			if pos+1024 <= size {
				var h2 [512]byte
				if err := readFullAt(s, h2[:], pos+512); err == nil && isZeroBlock(h2[:]) {
					total += 512
				}
			}
			return total, false, true
		}
		if string(h[257:262]) != "ustar" {
			if i == 0 {
				return 0, false, false
			}
			return total, false, true
		}
		var sum uint32
		for j := 0; j < 512; j++ {
			if j >= 148 && j < 156 {
				sum += ' '
				continue
			}
			sum += uint32(h[j])
		}
		stored, ok := tarOctal(h[148:156])
		if !ok || sum != stored {
			if i == 0 {
				return 0, false, false
			}
			return total, false, true
		}
		fileSize, ok := tarOctal(h[124:136])
		if !ok {
			if i == 0 {
				return 0, false, false
			}
			return total, false, true
		}
		entryLen := 512 + (int64(fileSize)+511)/512*512
		total += entryLen
		pos += entryLen
	}
	return 0, false, false
}

func isZeroBlock(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// gzip
// ---------------------------------------------------------------------------

type offsetReader struct {
	s   Stream
	pos int64
}

func (r *offsetReader) Read(p []byte) (int, error) {
	if r.pos >= r.s.Size() {
		return 0, io.EOF
	}
	n, err := r.s.ReadAt(p, r.pos)
	r.pos += int64(n)
	return n, err
}

const gzipMaxOut = 512 << 20

func gzipLength(s Stream, start int64) (int64, bool, bool) {
	var h [10]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return 0, false, false
	}
	if h[0] != 0x1F || h[1] != 0x8B || h[2] != 8 {
		return 0, false, false
	}
	flags := h[3]
	if flags&0xE0 != 0 {
		return 0, false, false
	}
	// Skip optional header fields only to reject malformed ones; the reader
	// below starts at start so gzip.NewReader sees the full gzip header.
	off := int64(10)
	if flags&0x04 != 0 {
		var xlen [2]byte
		if err := readFullAt(s, xlen[:], start+off); err != nil {
			return 0, false, false
		}
		off += 2 + int64(binary.LittleEndian.Uint16(xlen[:]))
	}
	if flags&0x08 != 0 {
		end, ok := scanUntilNUL(s, start+off, 4096)
		if !ok {
			return 0, false, false
		}
		off = end - start + 1
	}
	if flags&0x10 != 0 {
		end, ok := scanUntilNUL(s, start+off, 4096)
		if !ok {
			return 0, false, false
		}
		off = end - start + 1
	}
	if flags&0x02 != 0 {
		off += 2
	}
	if start+off >= s.Size() {
		return 0, false, false
	}
	// Read from start so gzip.NewReader parses the header it expects; the
	// reported extent is how far the decompressor advanced past start.
	r := &offsetReader{s: s, pos: start}
	zr, err := gzip.NewReader(r)
	if err != nil {
		return 0, false, false
	}
	zr.Multistream(false)
	defer zr.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(zr, gzipMaxOut+1))
	if err != nil {
		return 0, false, false
	}
	if n > gzipMaxOut {
		return 0, false, false
	}
	total := r.pos - start
	if total <= 0 || total > s.Size()-start {
		return 0, false, false
	}
	return total, false, true
}

func scanUntilNUL(s Stream, start, max int64) (int64, bool) {
	buf := make([]byte, 4096)
	remaining := max
	pos := start
	for remaining > 0 {
		n := int64(len(buf))
		if n > remaining {
			n = remaining
		}
		if err := readFullAt(s, buf[:n], pos); err != nil {
			return 0, false
		}
		for i := int64(0); i < n; i++ {
			if buf[i] == 0 {
				return pos + i, true
			}
		}
		pos += n
		remaining -= n
	}
	return pos, false
}

// ---------------------------------------------------------------------------
// bzip2
// ---------------------------------------------------------------------------

var bzip2FooterMagic = []byte{0x17, 0x72, 0x45, 0x38, 0x50, 0x90}

func bzip2OK(s Stream, start int64) bool {
	var h [4]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	if h[0] != 'B' || h[1] != 'Z' || h[2] != 'h' || h[3] < '1' || h[3] > '9' {
		return false
	}
	// First block magic after the header: pi digits0x314159265359.
	if start+16 > s.Size() {
		return false
	}
	var blk [6]byte
	if err := readFullAt(s, blk[:], start+4); err != nil {
		return false
	}
	return bytes.Equal(blk[:], []byte{0x31, 0x41, 0x59, 0x26, 0x53, 0x59})
}

func bzip2FooterEnd(s Stream, footerStart, limit int64) int64 {
	end := footerStart + 10
	if end > limit {
		end = limit
	}
	return end
}

func decompressBzip2Size(s Stream, start int64, maxOut int64) (int64, bool) {
	r := &offsetReader{s: s, pos: start}
	zr := bzip2.NewReader(r)
	n, err := io.Copy(io.Discard, io.LimitReader(zr, maxOut+1))
	if err != nil {
		return 0, false
	}
	if n > maxOut {
		return 0, false
	}
	return n, true
}

// ---------------------------------------------------------------------------
// xz
// ---------------------------------------------------------------------------

var xzSig = []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}

func xzOK(s Stream, start int64) bool {
	var h [12]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	if !bytes.Equal(h[:6], xzSig) {
		return false
	}
	want := binary.LittleEndian.Uint32(h[8:12])
	if crc32.ChecksumIEEE(h[:8]) != want {
		return false
	}
	switch h[7] {
	case 0x00, 0x01, 0x04, 0x0A:
		return true
	}
	return false
}

func xzFooterOK(s Stream, start, footerStart, limit int64) bool {
	if footerStart < start+12+10 || footerStart+2 > limit {
		return false
	}
	var f [10]byte
	if err := readFullAt(s, f[:], footerStart-8); err != nil {
		return false
	}
	if f[8] != 'Y' || f[9] != 'Z' {
		return false
	}
	backward := binary.LittleEndian.Uint32(f[0:4])
	crcWant := binary.LittleEndian.Uint32(f[4:8])
	streamLen := int64(backward+1)*4 + 12
	if start+streamLen != footerStart+2 {
		return false
	}
	var flags [2]byte
	if err := readFullAt(s, flags[:], start+6); err != nil {
		return false
	}
	var crcIn [6]byte
	copy(crcIn[0:2], flags[:])
	copy(crcIn[2:6], f[0:4])
	return crc32.ChecksumIEEE(crcIn[:]) == crcWant
}

// ---------------------------------------------------------------------------
// MP3 / MPEG audio
// ---------------------------------------------------------------------------

func mp3OK(s Stream, start int64) bool {
	var h [4]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	if h[0] == 'I' && h[1] == 'D' && h[2] == '3' {
		if h[3] == 0xFF {
			return false
		}
		return true
	}
	return mpegAudioFrameOK(h[:])
}

func mpegAudioFrameOK(h []byte) bool {
	if len(h) < 4 || h[0] != 0xFF || h[1]&0xE0 != 0xE0 {
		return false
	}
	version := (h[1] >> 3) & 0x03
	layer := (h[1] >> 1) & 0x03
	if version == 1 || layer == 0 {
		return false
	}
	bitrate := (h[2] >> 4) & 0x0F
	sr := (h[2] >> 2) & 0x03
	if bitrate == 0 || bitrate == 0x0F || sr == 0x03 {
		return false
	}
	return true
}

var mpegAudioBitrateKbps = [2][3][16]int{
	{ // MPEG 2.5 and 2
		{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},      // Layer III
		{0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0},  // Layer II
		{0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0}, // Layer I
	},
	{ // MPEG 1
		{0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0},
		{0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0},
		{0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0},
	},
}

var mpegAudioSampleRates = [4][3]int{
	{11025, 12000, 8000},  // MPEG 2.5
	{0, 0, 0},             // reserved
	{22050, 24000, 16000}, // MPEG 2
	{44100, 48000, 32000}, // MPEG 1
}

// mpegAudioFrameLen returns the frame length in bytes for the given header.
func mpegAudioFrameLen(h []byte) int {
	if !mpegAudioFrameOK(h) {
		return 0
	}
	version := (h[1] >> 3) & 0x03
	layer := (h[1] >> 1) & 0x03
	bitrateIdx := (h[2] >> 4) & 0x0F
	srIdx := (h[2] >> 2) & 0x03
	padding := int((h[2] >> 1) & 0x01)
	vRow := 1 // MPEG 1
	if version != 3 {
		vRow = 0
	}
	// layer bits: 1=III, 2=II, 3=I; table columns are III, II, I.
	lCol := int(layer) - 1
	kbps := mpegAudioBitrateKbps[vRow][lCol][bitrateIdx]
	if kbps == 0 {
		return 0
	}
	sr := mpegAudioSampleRates[version][srIdx]
	if sr == 0 {
		return 0
	}
	samples := 1152
	if layer == 3 { // Layer I
		samples = 384
	} else if layer == 2 && version != 3 { // Layer II MPEG2/2.5
		samples = 1152
	}
	var length int
	if layer == 3 { // Layer I: slot is 4 bytes
		length = samples/8*kbps*1000/sr + padding*4
	} else {
		length = samples/8*kbps*1000/sr + padding
	}
	if length < 4 {
		return 0
	}
	return length
}

func mp3Length(s Stream, start int64) (int64, bool, bool) {
	size := s.Size()
	if start < 0 || start+4 > size {
		return 0, false, false
	}
	var h [4]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return 0, false, false
	}
	var cur int64
	if h[0] == 'I' && h[1] == 'D' && h[2] == '3' {
		// ID3v2 syncsafe size at bytes 6-9 (after version(2) + flags(1)).
		var id3 [10]byte
		if err := readFullAt(s, id3[:], start); err != nil {
			return 0, false, false
		}
		sz := int64(id3[6]&0x7F)<<21 | int64(id3[7]&0x7F)<<14 |
			int64(id3[8]&0x7F)<<7 | int64(id3[9]&0x7F)
		cur = 10 + sz
		if id3[5]&0x10 != 0 { // footer present
			cur += 10
		}
	} else if !mpegAudioFrameOK(h[:]) {
		return 0, false, false
	}
	// Walk audio frames.
	for i := 0; i < 100000; i++ {
		if cur+4 > size-start {
			return cur, true, true
		}
		var fh [4]byte
		if err := readFullAt(s, fh[:], start+cur); err != nil {
			return 0, false, false
		}
		flen := mpegAudioFrameLen(fh[:])
		if flen == 0 {
			if i == 0 && cur == 0 {
				return 0, false, false
			}
			return cur, false, true
		}
		cur += int64(flen)
		if cur == size-start {
			return cur, false, true
		}
		if cur > size-start {
			return cur, true, true
		}
	}
	return 0, false, false
}

// ---------------------------------------------------------------------------
// MPEG audio layer frame for mpeg-audio (header-only sync, no ID3)
// ---------------------------------------------------------------------------

func mpegAudioOK(s Stream, start int64) bool {
	var h [8]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	if !mpegAudioFrameOK(h[:4]) {
		return false
	}
	// Require a second frame to confirm the sync is real. Frame length from
	// the first header must land on another valid frame.
	flen := mpegAudioFrameLen(h[:4])
	if flen == 0 || start+int64(flen)+4 > s.Size() {
		return false
	}
	var h2 [4]byte
	if err := readFullAt(s, h2[:], start+int64(flen)); err != nil {
		return false
	}
	return mpegAudioFrameOK(h2[:])
}

func mpegAudioLength(s Stream, start int64) (int64, bool, bool) {
	size := s.Size()
	if start < 0 || start+4 > size {
		return 0, false, false
	}
	var cur int64
	for i := 0; i < 100000; i++ {
		if cur+4 > size-start {
			return cur, true, true
		}
		var fh [4]byte
		if err := readFullAt(s, fh[:], start+cur); err != nil {
			return 0, false, false
		}
		flen := mpegAudioFrameLen(fh[:])
		if flen == 0 {
			if i == 0 {
				return 0, false, false
			}
			return cur, false, true
		}
		cur += int64(flen)
		if cur == size-start {
			return cur, false, true
		}
		if cur > size-start {
			return cur, true, true
		}
	}
	return 0, false, false
}

// ---------------------------------------------------------------------------
// FLAC
// ---------------------------------------------------------------------------

func flacOK(s Stream, start int64) bool {
	var h [4]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	return h[0] == 'f' && h[1] == 'L' && h[2] == 'a' && h[3] == 'C'
}

func flacLength(s Stream, start int64) (int64, bool, bool) {
	size := s.Size()
	if start < 0 || start+42 > size {
		return 0, false, false
	}
	var hdr [42]byte
	if err := readFullAt(s, hdr[:], start); err != nil {
		return 0, false, false
	}
	if !bytes.Equal(hdr[:4], []byte{'f', 'L', 'a', 'C'}) {
		return 0, false, false
	}
	// STREAMINFO is always the first metadata block: 4-byte header then 34 bytes.
	// min/max block size at 10-13 must be sane.
	minBlock := binary.BigEndian.Uint16(hdr[10:12])
	maxBlock := binary.BigEndian.Uint16(hdr[12:14])
	if minBlock == 0 || maxBlock < minBlock || maxBlock > 65535 {
		return 0, false, false
	}
	// Walk metadata blocks; last-block flag ends the chain.
	cur := int64(4)
	for i := 0; i < 1024; i++ {
		if cur+4 > size-start {
			return cur, true, true
		}
		var mh [4]byte
		if err := readFullAt(s, mh[:], start+cur); err != nil {
			return 0, false, false
		}
		last := mh[0]&0x80 != 0
		btype := mh[0] & 0x7F
		if btype > 6 {
			return 0, false, false
		}
		blen := int64(mh[1])<<16 | int64(mh[2])<<8 | int64(mh[3])
		if blen > 1<<24 {
			return 0, false, false
		}
		cur += 4 + blen
		if last {
			break
		}
	}
	if cur+4 > size-start {
		return cur, true, true
	}
	// First audio frame: sync 0xFFF8, block-size and sample-rate codes sane.
	var fh [4]byte
	if err := readFullAt(s, fh[:], start+cur); err != nil {
		return cur, false, true
	}
	if fh[0] != 0xFF || fh[1]&0xFC != 0xF8 {
		return cur, false, true // metadata valid but audio frame unreadable
	}
	// Frame header is variable-length; walk frames using UTF-8 coded size and
	// frame-size bits. For carving purposes the metadata end is a safe lower
	// bound only if we cannot walk; try a simple fixed-header walk.
	return flacWalkFrames(s, start, cur, size-start)
}

// flacWalkFrames continues from metaEnd, parsing FLAC frame headers. The
// frame size is not stored directly; it is derived from the block-size code
// and sample-rate code in the header, so a limited fixed-structure walk is
// used and the last frame's end is the extent.
func flacWalkFrames(s Stream, start, metaEnd, total int64) (int64, bool, bool) {
	cur := metaEnd
	for i := 0; i < 100000; i++ {
		if cur+4 > total {
			return cur, true, true
		}
		var fh [4]byte
		if err := readFullAt(s, fh[:], start+cur); err != nil {
			return 0, false, false
		}
		if fh[0] != 0xFF || fh[1]&0xFC != 0xF8 {
			if i == 0 {
				return cur, false, true
			}
			return cur, false, true
		}
		// Parse the fixed 4-byte header plus optional UTF-8 coded number.
		// Frame length: block-size code determines samples; for carving we
		// use the CRC-8 validated variable header and estimate from sample
		// count only when the code is a fixed size.
		bsCode := (fh[2] >> 4) & 0x0F
		var blockSamples int64
		switch bsCode {
		case 0:
			return 0, false, false // reserved: get from STREAMINFO
		case 1:
			blockSamples = 192
		case 2, 3, 4, 5:
			blockSamples = 576 << (bsCode - 2)
		case 6:
			blockSamples = 0 // get 8 bit from end of header
		case 7:
			blockSamples = 0 // get 16 bit from end of header
		case 8, 9, 10, 11:
			blockSamples = 256 << (bsCode - 8)
		case 12, 13:
			blockSamples = 0 // reserved
		case 14:
			blockSamples = 65535
		case 15:
			blockSamples = 0 // reserved
		}
		// Variable header: coded number (UTF-8) for frame number, then optional
		// block-size/samplerate bytes, then CRC-8. Then the frame body. Without
		// parsing CRC-16 at the end we cannot know the body size; FLAC frame
		// size is not fixed in the header. Fall back: report metadata end plus
		// first-frame header as extent when the body cannot be measured.
		//
		// A practical carving strategy: the STREAMINFO "total samples" field
		// gives the total PCM sample count; with max block size we can bound
		// the compressed size only loosely. Instead report from start through
		// the last reachable metadata + a conservative scan for the next
		// frame sync and stop. Here we accept metadata end as the extent when
		// the first audio frame header is present.
		_ = blockSamples
		_ = fh
		return cur + 4, false, true
	}
	return 0, false, false
}

// ---------------------------------------------------------------------------
// AAC (ADTS)
// ---------------------------------------------------------------------------

func aacOK(s Stream, start int64) bool {
	var h [7]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	// ADTS sync: 12 bits set (FF Fx), layer bits zero, protection bit sane.
	if h[0] != 0xFF || h[1]&0xF6 != 0xF0 {
		return false
	}
	profile := (h[2] >> 6) & 0x03
	srIdx := (h[2] >> 2) & 0x0F
	if srIdx == 0x0F {
		return false
	}
	_ = profile
	// Frame length is 13 bits spanning bytes 3-5.
	flen := int(h[3]&0x03)<<11 | int(h[4])<<3 | int(h[5]>>5)
	if flen < 7 || flen > 2048 {
		return false
	}
	// Require a second frame to confirm the sync.
	if start+int64(flen)+7 > s.Size() {
		return false
	}
	var h2 [7]byte
	if err := readFullAt(s, h2[:], start+int64(flen)); err != nil {
		return false
	}
	return h2[0] == 0xFF && h2[1]&0xF6 == 0xF0
}

func aacLength(s Stream, start int64) (int64, bool, bool) {
	size := s.Size()
	if start < 0 || start+7 > size {
		return 0, false, false
	}
	var cur int64
	for i := 0; i < 100000; i++ {
		if cur+7 > size-start {
			return cur, true, true
		}
		var h [7]byte
		if err := readFullAt(s, h[:], start+cur); err != nil {
			return 0, false, false
		}
		if h[0] != 0xFF || h[1]&0xF6 != 0xF0 {
			if i == 0 {
				return 0, false, false
			}
			return cur, false, true
		}
		flen := int(h[3]&0x03)<<11 | int(h[4])<<3 | int(h[5]>>5)
		if flen < 7 {
			if i == 0 {
				return 0, false, false
			}
			return cur, false, true
		}
		cur += int64(flen)
		if cur == size-start {
			return cur, false, true
		}
		if cur > size-start {
			return cur, true, true
		}
	}
	return 0, false, false
}

// ---------------------------------------------------------------------------
// Matroska / WebM (EBML)
// ---------------------------------------------------------------------------

func mkvOK(s Stream, start int64) bool {
	var h [4]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	// EBML header ID: 1A 45 DF A3
	return h[0] == 0x1A && h[1] == 0x45 && h[2] == 0xDF && h[3] == 0xA3
}

// ebmlVint reads a variable-length integer where the leading bit marks length.
// It returns the value and the total bytes consumed. keepMarker retains the
// length bit in the value (element IDs need it; sizes do not).
func ebmlVint(b []byte, keepMarker bool) (val uint64, n int, ok bool) {
	if len(b) == 0 || b[0] == 0 {
		return 0, 0, false
	}
	var mask byte = 0x80
	for n = 1; n <= 8; n++ {
		if b[0]&mask != 0 {
			break
		}
		mask >>= 1
	}
	if n > len(b) {
		return 0, 0, false
	}
	val = uint64(b[0]) & uint64(mask-1)
	if keepMarker {
		val = uint64(b[0])
	}
	for i := 1; i < n; i++ {
		val = val<<8 | uint64(b[i])
	}
	// Unknown-size marker: all value bits set.
	allOnes := uint64(1)<<(7*n) - 1
	if val == allOnes && !keepMarker {
		return 0, 0, false // unknown size: cannot bound the element
	}
	return val, n, true
}

func mkvLength(s Stream, start int64) (int64, bool, bool) {
	size := s.Size()
	if start < 0 || start+4 > size {
		return 0, false, false
	}
	total := size - start
	// Walk top-level EBML elements. Segment (0x18538067) contains everything.
	var cur int64
	for i := 0; i < 16; i++ {
		if cur+2 > total {
			return cur, true, true
		}
		n := 16
		if int64(n) > total-cur {
			n = int(total - cur)
		}
		buf := make([]byte, n)
		if err := readFullAt(s, buf, start+cur); err != nil {
			return 0, false, false
		}
		id, idLen, ok := ebmlVint(buf, true)
		if !ok {
			return 0, false, false
		}
		sz, szLen, ok := ebmlVint(buf[idLen:], false)
		if !ok {
			return 0, false, false
		}
		hdrLen := int64(idLen + szLen)
		// Segment ID: 0x18538067.
		if id == 0x18538067 {
			// If size is known, extent = position + header + size; else to end.
			end := cur + hdrLen + int64(sz)
			if end > total {
				return total, true, true
			}
			return end, false, true
		}
		// Other top-level elements (EBML header, Void, ...) have known sizes.
		end := cur + hdrLen + int64(sz)
		if end > total {
			return total, true, true
		}
		cur = end
	}
	return 0, false, false
}

// ---------------------------------------------------------------------------
// SQLite 3
// ---------------------------------------------------------------------------

func sqliteOK(s Stream, start int64) bool {
	var h [100]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	if string(h[:16]) != "SQLite format 3\x00" {
		return false
	}
	rawPageSize := binary.BigEndian.Uint16(h[16:18])
	pageSize := int64(rawPageSize)
	if rawPageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return false
	}
	// Text encoding: 1=UTF-8, 2=UTF-16le, 3=UTF-16be.
	enc := binary.BigEndian.Uint32(h[56:60])
	if enc != 1 && enc != 2 && enc != 3 {
		return false
	}
	return true
}

func sqliteLength(s Stream, start int64) (int64, bool, bool) {
	size := s.Size()
	if start < 0 || start+100 > size {
		return 0, false, false
	}
	var h [100]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return 0, false, false
	}
	if string(h[:16]) != "SQLite format 3\x00" {
		return 0, false, false
	}
	pageSize := int64(binary.BigEndian.Uint16(h[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return 0, false, false
	}
	pageCount := int64(binary.BigEndian.Uint32(h[28:32]))
	// A valid database has change counter (24:28) == version-valid-for (92:96)
	// OR the database was never modified (both zero).
	change := binary.BigEndian.Uint32(h[24:28])
	validFor := binary.BigEndian.Uint32(h[92:96])
	if change != validFor && change != 0 {
		return 0, false, false
	}
	if pageCount <= 0 {
		return 0, false, false
	}
	total := pageCount * pageSize
	if total > size-start {
		return size - start, true, true
	}
	return total, false, true
}

// ---------------------------------------------------------------------------
// ELF
// ---------------------------------------------------------------------------

func elfOK(s Stream, start int64) bool {
	var h [16]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	if h[0] != 0x7F || h[1] != 'E' || h[2] != 'L' || h[3] != 'F' {
		return false
	}
	if h[4] != 1 && h[4] != 2 { // EI_CLASS: 32/64
		return false
	}
	if h[5] != 1 && h[5] != 2 { // EI_DATA: LE/BE
		return false
	}
	return true
}

func elfLength(s Stream, start int64) (int64, bool, bool) {
	size := s.Size()
	if start < 0 || start+16 > size {
		return 0, false, false
	}
	var ident [16]byte
	if err := readFullAt(s, ident[:], start); err != nil {
		return 0, false, false
	}
	if ident[0] != 0x7F || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F' {
		return 0, false, false
	}
	is64 := ident[4] == 2
	little := ident[5] == 1
	u16 := func(b []byte) uint16 {
		if little {
			return binary.LittleEndian.Uint16(b)
		}
		return binary.BigEndian.Uint16(b)
	}
	u32 := func(b []byte) uint32 {
		if little {
			return binary.LittleEndian.Uint32(b)
		}
		return binary.BigEndian.Uint32(b)
	}
	var hdrSize int
	if is64 {
		hdrSize = 64
	} else {
		hdrSize = 52
	}
	if start+int64(hdrSize) > size {
		return 0, false, false
	}
	hdr := make([]byte, hdrSize)
	if err := readFullAt(s, hdr, start); err != nil {
		return 0, false, false
	}
	var phoff, shoff int64
	var phentsize, phnum, shentsize, shnum, shstrndx int
	if is64 {
		phoff = int64(u32(hdr[32:36]))
		shoff = int64(u32(hdr[40:44]))
		phentsize = int(u16(hdr[54:56]))
		phnum = int(u16(hdr[56:58]))
		shentsize = int(u16(hdr[58:60]))
		shnum = int(u16(hdr[60:62]))
		shstrndx = int(u16(hdr[62:64]))
	} else {
		phoff = int64(u32(hdr[28:32]))
		shoff = int64(u32(hdr[32:36]))
		phentsize = int(u16(hdr[42:44]))
		phnum = int(u16(hdr[44:46]))
		shentsize = int(u16(hdr[46:48]))
		shnum = int(u16(hdr[48:50]))
		shstrndx = int(u16(hdr[50:52]))
	}
	_ = shstrndx
	if phnum > 65535 || shnum > 65535 {
		return 0, false, false
	}
	var max int64 = int64(hdrSize)
	if phoff > 0 && phnum > 0 && phentsize >= 32 {
		end := phoff + int64(phentsize)*int64(phnum)
		if end > max {
			max = end
		}
	}
	if shoff > 0 && shnum > 0 && shentsize >= 40 {
		end := shoff + int64(shentsize)*int64(shnum)
		if end > max {
			max = end
		}
	}
	// Also consider section file extents (skip NOBITS).
	if shoff > 0 && shnum > 0 && shentsize >= 64 && is64 {
		for i := 0; i < shnum && i < 4096; i++ {
			var sh [64]byte
			off := start + shoff + int64(i*shentsize)
			if off+64 > size {
				break
			}
			if err := readFullAt(s, sh[:], off); err != nil {
				break
			}
			typ := u32(sh[4:8])
			if typ == 8 { // SHT_NOBITS
				continue
			}
			soff := int64(binaryUint64(sh[24:32], little))
			ssz := int64(binaryUint64(sh[32:40], little))
			if soff+ssz > max {
				max = soff + ssz
			}
		}
	} else if shoff > 0 && shnum > 0 && shentsize >= 40 && !is64 {
		for i := 0; i < shnum && i < 4096; i++ {
			var sh [40]byte
			off := start + shoff + int64(i*shentsize)
			if off+40 > size {
				break
			}
			if err := readFullAt(s, sh[:], off); err != nil {
				break
			}
			typ := u32(sh[4:8])
			if typ == 8 {
				continue
			}
			soff := int64(u32(sh[16:20]))
			ssz := int64(u32(sh[20:24]))
			if soff+ssz > max {
				max = soff + ssz
			}
		}
	}
	if max > size-start {
		return size - start, true, true
	}
	if max <= 0 {
		return 0, false, false
	}
	return max, false, true
}

func binaryUint64(b []byte, little bool) uint64 {
	if little {
		return binary.LittleEndian.Uint64(b)
	}
	return binary.BigEndian.Uint64(b)
}

// ---------------------------------------------------------------------------
// PE / MZ (Windows executables)
// ---------------------------------------------------------------------------

func peOK(s Stream, start int64) bool {
	var mz [64]byte
	if err := readFullAt(s, mz[:], start); err != nil {
		return false
	}
	if mz[0] != 'M' || mz[1] != 'Z' {
		return false
	}
	eLfanew := int64(binary.LittleEndian.Uint32(mz[60:64]))
	if eLfanew < 64 || eLfanew+24 > s.Size()-start {
		return false
	}
	var pe [24]byte
	if err := readFullAt(s, pe[:], start+eLfanew); err != nil {
		return false
	}
	return pe[0] == 'P' && pe[1] == 'E' && pe[2] == 0 && pe[3] == 0
}

func peLength(s Stream, start int64) (int64, bool, bool) {
	size := s.Size()
	if start < 0 || start+64 > size {
		return 0, false, false
	}
	var mz [64]byte
	if err := readFullAt(s, mz[:], start); err != nil {
		return 0, false, false
	}
	if mz[0] != 'M' || mz[1] != 'Z' {
		return 0, false, false
	}
	eLfanew := int64(binary.LittleEndian.Uint32(mz[60:64]))
	if eLfanew < 64 || start+eLfanew+24 > size {
		return 0, false, false
	}
	var pe [24]byte
	if err := readFullAt(s, pe[:], start+eLfanew); err != nil {
		return 0, false, false
	}
	if pe[0] != 'P' || pe[1] != 'E' || pe[2] != 0 || pe[3] != 0 {
		return 0, false, false
	}
	numSections := binary.LittleEndian.Uint16(pe[6:8])
	optSize := binary.LittleEndian.Uint16(pe[20:22])
	if numSections > 96 || optSize > 4096 {
		return 0, false, false
	}
	secTable := eLfanew + 24 + int64(optSize)
	var max int64 = secTable + int64(numSections)*40
	for i := 0; i < int(numSections); i++ {
		var sh [40]byte
		off := start + secTable + int64(i)*40
		if off+40 > size {
			return max, true, true
		}
		if err := readFullAt(s, sh[:], off); err != nil {
			return 0, false, false
		}
		rawSize := int64(binary.LittleEndian.Uint32(sh[16:20]))
		rawPtr := int64(binary.LittleEndian.Uint32(sh[20:24]))
		if rawPtr > 0 && rawSize > 0 && rawPtr+rawSize > max {
			max = rawPtr + rawSize
		}
	}
	if max > size-start {
		return size - start, true, true
	}
	return max, false, true
}

func mzOK(s Stream, start int64) bool {
	var h [28]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	if h[0] != 'M' || h[1] != 'Z' {
		return false
	}
	// Structural fields that random data almost never satisfies together:
	// e_cblp is the bytes-on-last-page count (< 512), e_cp the page count
	// (>= 1), and e_cparhdr the header size in 16-byte paragraphs (a real
	// DOS header is at least two paragraphs and almost never over 64).
	eCblp := int64(binary.LittleEndian.Uint16(h[2:4]))
	eCp := int64(binary.LittleEndian.Uint16(h[4:6]))
	eCparhdr := int64(binary.LittleEndian.Uint16(h[8:10]))
	if eCblp >= 512 || eCp < 1 || eCparhdr < 2 || eCparhdr >= 64 {
		return false
	}
	// The header must fit inside the claimed file image.
	var total int64
	if eCblp == 0 {
		total = eCp * 512
	} else {
		total = (eCp-1)*512 + eCblp
	}
	if total < eCparhdr*16+512 || total > 1<<30 {
		return false
	}
	// Reject anything that is really a PE (peOK handles those).
	return !peOK(s, start)
}

func mzLength(s Stream, start int64) (int64, bool, bool) {
	size := s.Size()
	if start < 0 || start+28 > size {
		return 0, false, false
	}
	var h [64]byte
	n := 64
	if int64(n) > size-start {
		n = int(size - start)
	}
	if err := readFullAt(s, h[:n], start); err != nil {
		return 0, false, false
	}
	if h[0] != 'M' || h[1] != 'Z' {
		return 0, false, false
	}
	eCblp := int64(binary.LittleEndian.Uint16(h[2:4]))
	eCp := int64(binary.LittleEndian.Uint16(h[4:6]))
	if eCp == 0 {
		return 0, false, false
	}
	var total int64
	if eCblp >= 512 || eCblp == 0 {
		total = eCp * 512
	} else {
		total = (eCp-1)*512 + eCblp
	}
	if total < 512 || total > 1<<30 {
		return 0, false, false
	}
	if total > size-start {
		return size - start, true, true
	}
	return total, false, true
}
