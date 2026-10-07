package recovery

import "encoding/binary"

// jpegOK requires a real first segment marker after SOI. Without it the
// three-byte header produces a candidate every ~16 MiB of high-entropy data.
func jpegOK(s Stream, start int64) bool {
	var h [4]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	// SOI is FF D8, the next two bytes are the first segment marker.
	if h[0] != 0xFF || h[1] != 0xD8 || h[2] != 0xFF {
		return false
	}
	switch h[3] {
	case 0xD8, 0xD9, 0x01, 0xFF: // SOI/EOI/TEM or a bare 0xFF run
		return false
	}
	return h[3] >= 0xC0 && h[3] <= 0xFE
}

// gifOK extends the four-byte "GIF8" header with its version bytes, which the
// scanner cannot include in the magic number because "GIF87a" and "GIF89a"
// are both legal and distinct.
func gifOK(s Stream, start int64) bool {
	var h [6]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	return h[0] == 'G' && h[1] == 'I' && h[2] == 'F' && h[3] == '8' &&
		(h[4] == '7' || h[4] == '9') && h[5] == 'a'
}

// zipOK checks the local file header layout: a sane version and a compression
// method inside the range ZIP actually defines.
func zipOK(s Stream, start int64) bool {
	// sig, version needed, flags and method: 10 bytes is all this needs.
	var h [10]byte
	if err := readFullAt(s, h[:], start); err != nil {
		return false
	}
	version := binary.LittleEndian.Uint16(h[4:6])
	method := binary.LittleEndian.Uint16(h[8:10])
	return version <= 1023 && method <= 12
}

// bmpLength reads the BITMAPFILEHEADER and the DIB header type. "BM" is too
// weak a header to trust without them.
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
		return 0, false, false // reserved words must be zero
	}
	offBits := int64(binary.LittleEndian.Uint32(h[10:14]))
	switch binary.LittleEndian.Uint32(h[14:18]) {
	case 12, 40, 52, 56, 64, 108, 124: // OS/2 and Windows DIB headers
	default:
		return 0, false, false
	}
	if size < 54 || size > 1<<31 || offBits < 14 || offBits > size {
		return 0, false, false
	}
	return size, false, true
}

// riffLength builds a length function for one RIFF form type. A size field of
// 0xFFFFFFFF is the streaming convention and means "to the end of the source".
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

// mp4Length walks the top-level ISO-BMFF box chain from start. Each step reads
// only a 16-byte box header, so a multi-gigabyte "mdat" is skipped in O(1).
// A box type outside printable ASCII, a size below its own header or a box
// that would start past the end of the source all reject the candidate.
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
			return total, true, true // fewer bytes left than a box header
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
			// The first box is the "ftyp" box this candidate was matched on;
			// a brand table never gets near 4 KiB, so anything else is noise.
			if boxSize < 16 || boxSize > 4096 {
				return 0, false, false
			}
		}
		switch boxSize {
		case 0: // box extends to the end of the file by definition
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
	return 0, false, false // pathological box count: do not trust the walk
}

// zipFooterEnd consumes the whole end-of-central-directory record: the four
// signature bytes the scanner matched, the fixed 18 bytes that follow them and
// the variable-length comment they declare.
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

// pdfFooterEnd swallows the CR/LF that conventionally follow the EOF marker.
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

// boxType reports whether b looks like an ISO-BMFF box type: four printable
// ASCII bytes. Random data almost never passes this together with sane sizes.
func boxType(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}
