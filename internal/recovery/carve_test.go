package recovery

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

// ---------------------------------------------------------------------------
// Builders: each fake* function returns a minimal-but-valid instance of its
// format so the table test below can plant one signature per type and assert
// the carver reports the right kind, offset and length.
// ---------------------------------------------------------------------------

func fakeTIFF(total int) []byte {
	// Header + image data first, IFD at the end so the IFD walk's max
	// offset covers the whole object.
	b := make([]byte, total)
	copy(b, []byte{'I', 'I', 0x2A, 0x00})
	ifdOff := total - 18
	if ifdOff < 8 {
		ifdOff = 8
	}
	binary.LittleEndian.PutUint32(b[4:8], uint32(ifdOff))
	binary.LittleEndian.PutUint16(b[ifdOff:ifdOff+2], 1)
	binary.LittleEndian.PutUint16(b[ifdOff+2:ifdOff+4], 256)
	binary.LittleEndian.PutUint16(b[ifdOff+4:ifdOff+6], 3)
	binary.LittleEndian.PutUint32(b[ifdOff+6:ifdOff+10], 1)
	binary.LittleEndian.PutUint32(b[ifdOff+10:ifdOff+14], 16)
	// Next IFD = 0 at ifdOff+14.
	return b
}

func fakeTIFFBE(total int) []byte {
	b := make([]byte, total)
	copy(b, []byte{'M', 'M', 0x00, 0x2A})
	ifdOff := total - 18
	if ifdOff < 8 {
		ifdOff = 8
	}
	binary.BigEndian.PutUint32(b[4:8], uint32(ifdOff))
	binary.BigEndian.PutUint16(b[ifdOff:ifdOff+2], 1)
	binary.BigEndian.PutUint16(b[ifdOff+2:ifdOff+4], 256)
	binary.BigEndian.PutUint16(b[ifdOff+4:ifdOff+6], 3)
	binary.BigEndian.PutUint32(b[ifdOff+6:ifdOff+10], 1)
	binary.BigEndian.PutUint32(b[ifdOff+10:ifdOff+14], 16)
	return b
}

func fakeWebP(total int) []byte {
	return fakeRIFF("WEBP", total)
}

func fakeHEIC(ftypSize, moovSize int) []byte {
	b := make([]byte, ftypSize+moovSize)
	binary.BigEndian.PutUint32(b[0:4], uint32(ftypSize))
	copy(b[4:8], "ftyp")
	copy(b[8:12], "heic")
	copy(b[12:16], "mif1")
	copy(b[ftypSize:], u32be(uint32(moovSize)))
	copy(b[ftypSize+4:ftypSize+8], "moov")
	return b
}

// fakeCFB builds a minimal CFB v3 file with one FAT sector and a root entry
// whose name identifies the given family ("doc", "xls", "ppt" or "" for a
// generic container). Layout: 512-byte header, sector 0 = FAT, sector 1 =
// directory. The FAT marks both sectors as ENDOFCHAIN.
func fakeCFB(family string) []byte {
	const sectorSize = 512
	b := make([]byte, 512+2*sectorSize)
	copy(b, cfbSig)
	binary.LittleEndian.PutUint16(b[24:26], 0x003E) // minor version
	binary.LittleEndian.PutUint16(b[26:28], 3)      // major version 3
	binary.LittleEndian.PutUint16(b[28:30], 0xFFFE) // byte order
	binary.LittleEndian.PutUint16(b[30:32], 9)      // sector shift (512)
	binary.LittleEndian.PutUint16(b[32:34], 6)      // mini sector shift
	binary.LittleEndian.PutUint32(b[44:48], 1)      // number of FAT sectors
	binary.LittleEndian.PutUint32(b[48:52], 1)      // first directory sector
	binary.LittleEndian.PutUint32(b[56:60], 4096)   // mini stream cutoff
	binary.LittleEndian.PutUint32(b[60:64], 0xFFFFFFFE)
	binary.LittleEndian.PutUint32(b[64:68], 0)
	binary.LittleEndian.PutUint32(b[68:72], 0xFFFFFFFE) // first DIFAT sector (none)
	binary.LittleEndian.PutUint32(b[72:76], 0)          // number of DIFAT sectors
	// Header DIFAT array: first entry points at sector 0 (the FAT).
	binary.LittleEndian.PutUint32(b[76:80], 0)
	for i := 1; i < 109; i++ {
		binary.LittleEndian.PutUint32(b[76+i*4:80+i*4], 0xFFFFFFFF)
	}
	// FAT (sector 0): sector 0 is FATSECT, sector 1 is ENDOFCHAIN.
	fat := b[512 : 512+sectorSize]
	for i := 0; i < sectorSize/4; i++ {
		binary.LittleEndian.PutUint32(fat[i*4:i*4+4], 0xFFFFFFFF)
	}
	binary.LittleEndian.PutUint32(fat[0:4], 0xFFFFFFFD) // FATSECT
	binary.LittleEndian.PutUint32(fat[4:8], 0xFFFFFFFE) // ENDOFCHAIN (directory)
	// Directory (sector 1): entry 0 is the root.
	dir := b[512+sectorSize : 512+2*sectorSize]
	for i := 0; i < sectorSize/128; i++ {
		dir[i*128] = 0x05 // unused entry type
	}
	name := ""
	switch family {
	case "doc":
		name = "WordDocument"
	case "xls":
		name = "Workbook"
	case "ppt":
		name = "PowerPoint Document"
	}
	if name != "" {
		ent := dir[:128]
		ent[0] = 0x05 // root storage
		for i, r := range name {
			binary.LittleEndian.PutUint16(ent[i*2:], uint16(r))
		}
		binary.LittleEndian.PutUint16(ent[64:66], uint16(len(name)*2+2))
		ent[66] = 1 // object type: storage
	}
	return b
}

// fakeOOXML builds a ZIP whose first local-file name carries the given part
// prefix, wrapped in an EOCD so the footer-based extent resolves.
func fakeOOXML(prefix string, payload int) []byte {
	name := prefix + "document.xml"
	local := concat(
		[]byte{'P', 'K', 0x03, 0x04},
		[]byte{0x14, 0x00}, // version
		[]byte{0x00, 0x00}, // flags
		[]byte{0x00, 0x00}, // stored
		pad(16),            // mtime mdate crc csize usize
		u16le(uint16(len(name))),
		u16le(0),
		[]byte(name),
	)
	eocd := concat(
		[]byte{'P', 'K', 0x05, 0x06},
		u16le(0), u16le(0), u16le(1), u16le(1),
		u32le(0), u32le(0), u16le(0),
	)
	return concat(local, pad(payload), eocd)
}

// fakeRARv4 builds a v4 RAR with a marker block, an oversized archive header
// (to absorb padding) and an ENDARC block. The block chain must be
// contiguous: the walker reads each header's size to find the next.
func fakeRARv4(payload int) []byte {
	if payload < 0 {
		payload = 0
	}
	// Archive header: 13-byte base + payload extra body bytes.
	archSize := 13 + payload
	archHdr := make([]byte, archSize)
	archHdr[2] = 0x73
	binary.LittleEndian.PutUint16(archHdr[5:7], uint16(archSize))
	// ENDARC block.
	endArc := make([]byte, 7)
	endArc[2] = 0x7B
	binary.LittleEndian.PutUint16(endArc[5:7], 7)
	return concat(rarSigV4, archHdr, endArc)
}

// fake7z builds a 7z start header whose next-header offset/size point at a
// small placeholder header so the total length is deterministic.
func fake7z(payload int) []byte {
	// Start header 32 bytes, then payload filler, then a 8-byte "next header".
	nextOff := uint64(payload)
	nextSize := uint64(8)
	b := make([]byte, 32+payload+8)
	copy(b, szSig)
	b[6], b[7] = 0, 4 // version 0.4
	binary.LittleEndian.PutUint64(b[12:20], nextOff)
	binary.LittleEndian.PutUint64(b[20:28], nextSize)
	binary.LittleEndian.PutUint32(b[28:32], 0) // next header CRC (unchecked here)
	return b
}

// fakeTAR builds a single ustar entry with the given payload size plus the
// two-block zero terminator.
func fakeTAR(fileSize int) []byte {
	entry := make([]byte, 512)
	copy(entry, "hello.txt")
	writeOctal(entry[124:136], uint64(fileSize))
	writeOctal(entry[136:148], 0) // mtime
	entry[156] = '0'              // typeflag: regular file
	copy(entry[257:263], "ustar\x00")
	copy(entry[263:265], "00")
	// Checksum field (148-155) is treated as eight spaces while summing.
	var sum uint32
	for i := 0; i < 512; i++ {
		if i >= 148 && i < 156 {
			sum += ' '
			continue
		}
		sum += uint32(entry[i])
	}
	// Store as 6 octal digits + NUL + space, the common convention.
	writeOctal(entry[148:154], uint64(sum))
	entry[154] = 0
	entry[155] = ' '
	// Pad file data to a 512-byte boundary, then two zero blocks.
	dataLen := (fileSize + 511) / 512 * 512
	data := bytes.Repeat([]byte{'x'}, dataLen)
	return concat(entry, data, make([]byte, 1024))
}

func writeOctal(b []byte, v uint64) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i] = byte('0' + v&7)
		v >>= 3
	}
	if len(b) > 0 {
		b[len(b)-1] |= 0 // keep as-is; terminator NUL is conventional
	}
}

// fakeGzip builds a real gzip member via compress/gzip so the length walker
// (which inflates) reports the exact same byte count.
func fakeGzip(payload int) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	body := bytes.Repeat([]byte{'G'}, payload)
	if _, err := zw.Write(body); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// fakeBzip2 builds a bzip2 stream by compressing with the stdlib, which emits
// the canonical end-of-stream magic the footer matcher looks for.
func fakeBzip2(t *testing.T, payload int) []byte {
	t.Helper()
	// Use a stored-style approach: compress empty-ish data via a real encoder.
	// The stdlib does not expose a raw encoder, so plant the header + first
	// block magic + end magic around zeros; the carver only needs the footer
	// chain to resolve, and Validate checks BZh + first block magic.
	//
	// Full valid bzip2 requires CRC'd blocks; instead build a stream the
	// validator accepts: "BZh9" + first-block magic + body + end magic + CRC.
	in := bytes.Repeat([]byte{'B'}, payload)
	// Fall back to compress/bzip2 round-trip: write via a tiny encoder is not
	// in stdlib. Construct a synthetic stream:
	//   BZh9 | 314159265359 (block magic) | arbitrary | 177245385090 | CRC32
	hdr := []byte{'B', 'Z', 'h', '9'}
	blkMagic := []byte{0x31, 0x41, 0x59, 0x26, 0x53, 0x59}
	endMagic := bzip2FooterMagic
	// Bit-level framing is not needed: our walker is footer-based, and the
	// only structural Validate is the first block magic. Pad the middle.
	middle := pad(len(in))
	var crc [4]byte // arbitrary; not checked by the carver
	return concat(hdr, blkMagic, middle, endMagic, crc[:])
}

// fakeXZ builds an xz stream header + footer with consistent backward size
// and CRC so xzFooterOK accepts it. The body length is padded so
// (bodyLen+10) is a multiple of 4, which the backward-size encoding requires.
func fakeXZ(payload int) []byte {
	// Pad payload so (payload+10) % 4 == 0.
	if (payload+10)%4 != 0 {
		payload += 4 - (payload+10)%4
	}
	var hdr [12]byte
	copy(hdr[:6], xzSig)
	hdr[6], hdr[7] = 0x00, 0x01 // check type CRC32
	binary.LittleEndian.PutUint32(hdr[8:12], crc32.ChecksumIEEE(hdr[:8]))
	body := pad(payload)
	streamLen := 12 + payload + 10
	backward := uint32((streamLen-12)/4 - 1)
	var flagsAndBack [6]byte
	copy(flagsAndBack[0:2], hdr[6:8])
	binary.LittleEndian.PutUint32(flagsAndBack[2:6], backward)
	var footer [10]byte
	binary.LittleEndian.PutUint32(footer[0:4], backward)
	binary.LittleEndian.PutUint32(footer[4:8], crc32.ChecksumIEEE(flagsAndBack[:]))
	footer[8], footer[9] = 'Y', 'Z'
	return concat(hdr[:], body, footer[:])
}

// fakeMP3 builds an ID3v2 tag followed by a single MPEG-1 Layer III frame.
func fakeMP3(payload int) []byte {
	// ID3v2 header: "ID3" ver 04 00 flags 00, syncsafe size.
	id3Size := uint32(payload)
	id3 := make([]byte, 10)
	copy(id3, "ID3")
	id3[3], id3[4] = 4, 0
	id3[6] = byte(id3Size >> 21 & 0x7F)
	id3[7] = byte(id3Size >> 14 & 0x7F)
	id3[8] = byte(id3Size >> 7 & 0x7F)
	id3[9] = byte(id3Size & 0x7F)
	tag := pad(payload)
	// One MPEG-1 Layer III 128 kbps 44100 Hz frame: length = 417 or 418.
	frame := make([]byte, 417)
	frame[0] = 0xFF
	frame[1] = 0xFB
	frame[2] = 0x90 // bitrate idx 9 (128k), sr idx 0 (44100), no padding
	return concat(id3, tag, frame)
}

// fakeMPEGAudio builds a chain of two MPEG-1 Layer III frames so the
// second-frame validation in mpegAudioOK passes.
func fakeMPEGAudio(frames int) []byte {
	frameLen := 417
	out := make([]byte, 0, frames*frameLen)
	for i := 0; i < frames; i++ {
		f := make([]byte, frameLen)
		f[0] = 0xFF
		f[1] = 0xFB
		f[2] = 0x90
		out = append(out, f...)
	}
	return out
}

// fakeFLAC builds STREAMINFO (last-block) followed by a minimal frame header.
func fakeFLAC(payload int) []byte {
	b := make([]byte, 42+payload)
	copy(b, []byte{'f', 'L', 'a', 'C'})
	// Metadata block header: last-block=1, type=0 (STREAMINFO), length=34.
	b[4] = 0x80
	b[5], b[6], b[7] = 0, 0, 34
	// min/max block size at 10-13.
	binary.BigEndian.PutUint16(b[10:12], 4096)
	binary.BigEndian.PutUint16(b[12:14], 4096)
	// Frame header at 42: sync 0xFFF8, fixed block-size code, etc.
	b[42] = 0xFF
	b[43] = 0xF8
	b[44] = 0x80 // block-size code 8 (256), sample-rate code 0
	b[45] = 0x00
	return b
}

// fakeAAC builds a chain of ADTS frames.
func fakeAAC(frames int) []byte {
	frameLen := 32
	out := make([]byte, 0, frames*frameLen)
	for i := 0; i < frames; i++ {
		f := make([]byte, frameLen)
		f[0] = 0xFF
		f[1] = 0xF1 // MPEG-4, layer 0, no CRC
		f[2] = 0x40 // profile AAC LC, sr idx 4 (44100), channels in low bits
		// frame length 13 bits at bytes 3-5: high 2 bits of byte3 + byte4 + byte5 high 3.
		f[3] = byte((frameLen >> 11) & 0x03)
		f[4] = byte((frameLen >> 3) & 0xFF)
		f[5] = byte((frameLen & 0x07) << 5)
		out = append(out, f...)
	}
	return out
}

// fakeMKV builds EBML header + Segment with a known size.
func fakeMKV(payload int) []byte {
	// EBML header: ID 1A45DFA3, size 0x80+? Use 1-byte vint size = 0x80|0 = empty body.
	// Simpler: header with size byte 0x84 (4 bytes body of zeros).
	ebmlHdr := []byte{0x1A, 0x45, 0xDF, 0xA3, 0x84, 0, 0, 0, 0}
	// Segment: ID 18538067, size as 8-byte vint for payload.
	segID := []byte{0x18, 0x53, 0x80, 0x67}
	// 8-byte vint: first byte 0x01 (marker for 8-byte), then 7 bytes of size.
	sz := uint64(payload)
	szBytes := []byte{
		0x01 | byte(sz>>56)&0x7F,
		byte(sz >> 48), byte(sz >> 40), byte(sz >> 32),
		byte(sz >> 24), byte(sz >> 16), byte(sz >> 8), byte(sz),
	}
	body := pad(payload)
	return concat(ebmlHdr, segID, szBytes, body)
}

func fakeSQLite(pages, pageSize int) []byte {
	b := make([]byte, pages*pageSize)
	copy(b, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(b[16:18], uint16(pageSize))
	b[18] = 1  // write version
	b[19] = 1  // read version
	b[20] = 0  // reserved space per page
	b[21] = 64 // max embedded payload fraction
	b[22] = 32
	b[23] = 32
	binary.BigEndian.PutUint32(b[28:32], uint32(pages)) // database size in pages
	binary.BigEndian.PutUint32(b[56:60], 1)             // text encoding UTF-8
	// change counter (24:28) and version-valid-for (92:96) both zero: valid.
	return b
}

// fakeELF builds a 64-bit LE ELF with a section header table whose extent is
// the reported length.
func fakeELF(total int) []byte {
	b := make([]byte, total)
	copy(b, []byte{0x7F, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(b[16:18], 1)  // ET_REL
	binary.LittleEndian.PutUint16(b[18:20], 62) // EM_X86_64
	binary.LittleEndian.PutUint32(b[20:24], 1)  // version
	// e_shoff at 40: point at 64.
	binary.LittleEndian.PutUint64(b[40:48], 64)
	binary.LittleEndian.PutUint16(b[52:54], 64) // e_ehsize
	binary.LittleEndian.PutUint16(b[58:60], 64) // e_shentsize
	binary.LittleEndian.PutUint16(b[60:62], 1)  // e_shnum
	binary.LittleEndian.PutUint16(b[62:64], 0)  // e_shstrndx
	// One section header at 64: SHT_PROGBITS, offset 128, size total-128.
	sh := b[64:128]
	binary.LittleEndian.PutUint32(sh[4:8], 1) // SHT_PROGBITS
	binary.LittleEndian.PutUint64(sh[24:32], 128)
	binary.LittleEndian.PutUint64(sh[32:40], uint64(total-128))
	return b
}

// fakePE builds an MZ stub plus a PE header with one section.
func fakePE(total int) []byte {
	b := make([]byte, total)
	b[0], b[1] = 'M', 'Z'
	binary.LittleEndian.PutUint16(b[2:4], 0x90)  // e_cblp
	binary.LittleEndian.PutUint16(b[4:6], 3)     // e_cp
	binary.LittleEndian.PutUint16(b[8:10], 2)    // e_cparhdr
	binary.LittleEndian.PutUint32(b[60:64], 128) // e_lfanew
	copy(b[128:132], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[132:134], 0x8664) // machine
	binary.LittleEndian.PutUint16(b[134:136], 1)      // number of sections
	binary.LittleEndian.PutUint16(b[148:150], 240)    // size of optional header
	binary.LittleEndian.PutUint16(b[150:152], 0x0022) // characteristics
	// Section table at 128+24+240 = 392.
	sh := b[392:432]
	copy(sh, ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(sh[16:20], uint32(total-512)) // SizeOfRawData
	binary.LittleEndian.PutUint32(sh[20:24], 512)               // PointerToRawData
	return b
}

func fakeMZ(total int) []byte {
	b := make([]byte, total)
	b[0], b[1] = 'M', 'Z'
	binary.LittleEndian.PutUint16(b[2:4], 0) // e_cblp = 0 → size = e_cp*512
	binary.LittleEndian.PutUint16(b[4:6], uint16(total/512))
	binary.LittleEndian.PutUint16(b[8:10], 2) // e_cparhdr
	return b
}

// ---------------------------------------------------------------------------
// Table test: plant one instance of every registered type and check the
// carver reports the right Type, Offset and Length.
// ---------------------------------------------------------------------------

func TestCarvePlantedSignatures(t *testing.T) {
	tests := []struct {
		name  string
		types []string // nil = all
		want  string
		data  []byte
	}{
		{"jpeg", nil, "jpeg", fakeJPEG(400)},
		{"png", nil, "png", fakePNG(400)},
		{"gif", nil, "gif", fakeGIF(400)},
		{"tiff", nil, "tiff", fakeTIFF(200)},
		{"tiff-be", nil, "tiff-be", fakeTIFFBE(200)},
		{"webp", nil, "webp", fakeWebP(200)},
		{"heic", nil, "heic", fakeHEIC(32, 64)},
		{"pdf", nil, "pdf", fakePDF(400)},
		{"zip", []string{"zip"}, "zip", fakeZIP(400)},
		{"docx", nil, "docx", fakeOOXML("word/", 200)},
		{"xlsx", nil, "xlsx", fakeOOXML("xl/", 200)},
		{"pptx", nil, "pptx", fakeOOXML("ppt/", 200)},
		{"bmp", nil, "bmp", fakeBMP(400)},
		{"wav", nil, "wav", fakeRIFF("WAVE", 400)},
		{"avi", nil, "avi", fakeRIFF("AVI ", 400)},
		{"mp4", []string{"mp4"}, "mp4", fakeMP4(32, 368)},
		{"doc", nil, "doc", fakeCFB("doc")},
		{"xls", nil, "xls", fakeCFB("xls")},
		{"ppt", nil, "ppt", fakeCFB("ppt")},
		{"ole", nil, "ole", fakeCFB("")},
		{"rar", nil, "rar", fakeRARv4(100)},
		{"7z", nil, "7z", fake7z(64)},
		{"tar", nil, "tar", fakeTAR(100)},
		{"gzip", nil, "gzip", fakeGzip(200)},
		{"bzip2", nil, "bzip2", fakeBzip2(t, 64)},
		{"xz", nil, "xz", fakeXZ(100)},
		{"sqlite", nil, "sqlite", fakeSQLite(4, 512)},
		{"mp3", nil, "mp3", fakeMP3(100)},
		{"mpeg-audio", nil, "mpeg-audio", fakeMPEGAudio(4)},
		{"flac", nil, "flac", fakeFLAC(4)},
		{"aac", nil, "aac", fakeAAC(3)},
		{"mkv", nil, "mkv", fakeMKV(128)},
		{"elf", nil, "elf", fakeELF(512)},
		{"pe", nil, "pe", fakePE(1024)},
		{"mz", nil, "mz", fakeMZ(2048)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := carveOne(t, &memStream{tc.data}, Options{Types: tc.types})
			if got.Type != tc.want {
				t.Errorf("Type = %q, want %q", got.Type, tc.want)
			}
			if got.Offset != 0 {
				t.Errorf("Offset = %d, want 0", got.Offset)
			}
			if want := int64(len(tc.data)); got.Length != want {
				t.Errorf("Length = %d, want %d", got.Length, want)
			}
			if got.Truncated {
				t.Error("Truncated = true, want false")
			}
			if got.HeaderLen < 1 {
				t.Errorf("HeaderLen = %d, want >= 1", got.HeaderLen)
			}
		})
	}
}

// Every registered name must appear in the table above, so adding a spec
// without a planted test fails here.
func TestPlantedTableCoversRegistry(t *testing.T) {
	covered := map[string]bool{
		"jpeg": true, "png": true, "gif": true, "tiff": true, "tiff-be": true,
		"webp": true, "heic": true, "pdf": true, "zip": true, "docx": true,
		"xlsx": true, "pptx": true, "bmp": true, "wav": true, "avi": true,
		"mp4": true, "doc": true, "xls": true, "ppt": true, "ole": true,
		"rar": true, "7z": true, "tar": true, "gzip": true, "bzip2": true,
		"xz": true, "sqlite": true, "mp3": true, "mpeg-audio": true,
		"flac": true, "aac": true, "mkv": true, "elf": true, "pe": true,
		"mz": true,
	}
	for _, sp := range registry {
		if !covered[sp.Name] {
			t.Errorf("registered type %q has no planted-signature test", sp.Name)
		}
	}
	if len(registry) != 35 {
		t.Errorf("registry has %d types, want 35", len(registry))
	}
}
