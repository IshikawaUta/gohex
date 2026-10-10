package recovery

// registry holds every carveable type in display order. Specs are package-level
// values: the scanner never mutates them, so sharing pointers is safe.
//
// Order matters for overlapping families: HEIC precedes MP4 (both start at an
// ftyp box); DOCX/XLSX/PPTX precede plain ZIP (same local header); PE precedes
// MZ (every PE starts with MZ). The scanner reports the first match at a given
// offset and advances past it, so a more specific spec listed first wins.
var registry = []*Spec{
	sjpeg, spng, sgif, stiff, stiffbe, swebp, sheic, spdf,
	sdocx, sxlsx, sppx, szip,
	sbmp, swav, savi, smp4,
	sdoc, sxls, spp, sole,
	srar, ssz, star, sgzip, sbzip2, sxz,
	ssqlite, semp3, smpegaudio, sflac, saac, smkv,
	self, spe, smz,
}

var specByName = func() map[string]*Spec {
	m := make(map[string]*Spec, len(registry))
	for _, sp := range registry {
		m[sp.Name] = sp
	}
	return m
}()

var (
	// JPEG: SOI plus a first segment marker. The marker check matters —
	// "FF D8 FF" alone occurs roughly once per 16 MiB of random data, and most
	// of those hits have no "FF D9" after them, so validating the segment type
	// up front keeps the candidate queue clean.
	sjpeg = &Spec{
		Name: "jpeg", Display: "JPEG image", Ext: ".jpg",
		Header:   []byte{0xFF, 0xD8, 0xFF},
		Footer:   []byte{0xFF, 0xD9},
		Validate: jpegOK,
		MinSize:  64, MaxSize: 256 << 20,
	}

	// PNG: fixed 8-byte signature, IEND chunk terminator.
	spng = &Spec{
		Name: "png", Display: "PNG image", Ext: ".png",
		Header:  []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
		Footer:  []byte{'I', 'E', 'N', 'D', 0xAE, 0x42, 0x60, 0x82},
		MinSize: 40, MaxSize: 256 << 20,
	}

	// GIF: "GIF8" is only four bytes, so the 7a/9a version check is required.
	sgif = &Spec{
		Name: "gif", Display: "GIF image", Ext: ".gif",
		Header:   []byte{'G', 'I', 'F', '8'},
		Footer:   []byte{0x00, 0x3B},
		Validate: gifOK,
		MinSize:  14, MaxSize: 128 << 20,
	}

	// TIFF: classic little-endian magic "II*\0" with an IFD chain.
	stiff = &Spec{
		Name: "tiff", Display: "TIFF image (LE)", Ext: ".tif",
		Header:   []byte{'I', 'I', 0x2A, 0x00},
		Length:   tiffLength,
		Validate: tiffOK,
		MinSize:  8, MaxSize: 4 << 30,
	}

	// TIFF big-endian magic "MM\0*".
	stiffbe = &Spec{
		Name: "tiff-be", Display: "TIFF image (BE)", Ext: ".tif",
		Header:   []byte{'M', 'M', 0x00, 0x2A},
		Length:   tiffBELength,
		Validate: tiffBEOK,
		MinSize:  8, MaxSize: 4 << 30,
	}

	// WebP: RIFF container with form type "WEBP".
	swebp = &Spec{
		Name: "webp", Display: "WebP image", Ext: ".webp",
		Header:  []byte{'R', 'I', 'F', 'F'},
		Length:  webpLength,
		MinSize: 12, MaxSize: 256 << 20,
	}

	// HEIC/HEIF: ISO-BMFF ftyp with a HEIC-compatible brand. Registered
	// before mp4 so an ftyp-heic file is not mislabelled as generic MP4.
	sheic = &Spec{
		Name: "heic", Display: "HEIC/HEIF image", Ext: ".heic",
		Header:     []byte{'f', 't', 'y', 'p'},
		StartDelta: -4,
		Length:     mp4Length,
		Validate:   heicOK,
		MinSize:    16, MaxSize: 4 << 30,
	}

	// PDF: "%PDF-" header, "%%EOF" trailer with the usual CR/LF tail.
	spdf = &Spec{
		Name: "pdf", Display: "PDF document", Ext: ".pdf",
		Header:    []byte{'%', 'P', 'D', 'F', '-'},
		Footer:    []byte{'%', '%', 'E', 'O', 'F'},
		FooterEnd: pdfFooterEnd,
		MinSize:   32, MaxSize: 512 << 20,
	}

	// ZIP: local file header in, end-of-central-directory record out. The EOCD
	// is 22 bytes plus a comment of up to 65535 bytes, and cutting the record
	// short at the signature would yield an archive no tool can open, so the
	// record length is read back from the footer instead of assumed.
	szip = &Spec{
		Name: "zip", Display: "ZIP archive", Ext: ".zip",
		Header:    []byte{'P', 'K', 0x03, 0x04},
		Footer:    []byte{'P', 'K', 0x05, 0x06},
		FooterEnd: zipFooterEnd,
		Validate:  zipOK,
		MinSize:   40, MaxSize: 4 << 30,
	}

	// OOXML packages are ZIP archives whose first member lives under a known
	// part prefix. They are registered before plain zip so the more specific
	// type wins when both would match.
	sdocx = &Spec{
		Name: "docx", Display: "Word document (OOXML)", Ext: ".docx",
		Header:    []byte{'P', 'K', 0x03, 0x04},
		Footer:    []byte{'P', 'K', 0x05, 0x06},
		FooterEnd: zipFooterEnd,
		Validate:  ooxmlOK("word/"),
		MinSize:   40, MaxSize: 4 << 30,
	}

	sxlsx = &Spec{
		Name: "xlsx", Display: "Excel spreadsheet (OOXML)", Ext: ".xlsx",
		Header:    []byte{'P', 'K', 0x03, 0x04},
		Footer:    []byte{'P', 'K', 0x05, 0x06},
		FooterEnd: zipFooterEnd,
		Validate:  ooxmlOK("xl/"),
		MinSize:   40, MaxSize: 4 << 30,
	}

	sppx = &Spec{
		Name: "pptx", Display: "PowerPoint presentation (OOXML)", Ext: ".pptx",
		Header:    []byte{'P', 'K', 0x03, 0x04},
		Footer:    []byte{'P', 'K', 0x05, 0x06},
		FooterEnd: zipFooterEnd,
		Validate:  ooxmlOK("ppt/"),
		MinSize:   40, MaxSize: 4 << 30,
	}

	// BMP: "BM" alone is two ASCII bytes, so the size field, the reserved
	// words and the DIB header size all have to agree before a candidate is
	// queued.
	sbmp = &Spec{
		Name: "bmp", Display: "Bitmap image", Ext: ".bmp",
		Header:  []byte{'B', 'M'},
		Length:  bmpLength,
		MinSize: 54, MaxSize: 1 << 30,
	}

	// RIFF containers: the length lives at offset 4 and the form type at 8.
	swav = &Spec{
		Name: "wav", Display: "RIFF WAVE audio", Ext: ".wav",
		Header:  []byte{'R', 'I', 'F', 'F'},
		Length:  riffLength("WAVE"),
		MinSize: 44, MaxSize: 4 << 30,
	}

	savi = &Spec{
		Name: "avi", Display: "RIFF AVI video", Ext: ".avi",
		Header:  []byte{'R', 'I', 'F', 'F'},
		Length:  riffLength("AVI "),
		MinSize: 200, MaxSize: 8 << 30,
	}

	// MP4/MOV: the "ftyp" box sits four bytes into the file, so StartDelta
	// moves the reported start back over the size field and the box walker
	// takes it from there.
	smp4 = &Spec{
		Name: "mp4", Display: "MP4/MOV video", Ext: ".mp4",
		Header:     []byte{'f', 't', 'y', 'p'},
		StartDelta: -4,
		Length:     mp4Length,
		MinSize:    16, MaxSize: 8 << 30,
	}

	// OLE compound files. The four family-specific specs read the root
	// directory name; the generic ole spec is the low-confidence fallback for
	// containers whose root entry is unreadable or unfamiliar.
	sdoc = &Spec{
		Name: "doc", Display: "Word document (OLE)", Ext: ".doc",
		Header:   cfbSig,
		Length:   cfbLength,
		Validate: cfbFamilyIs("doc"),
		MinSize:  512, MaxSize: 2 << 30,
	}

	sxls = &Spec{
		Name: "xls", Display: "Excel spreadsheet (OLE)", Ext: ".xls",
		Header:   cfbSig,
		Length:   cfbLength,
		Validate: cfbFamilyIs("xls"),
		MinSize:  512, MaxSize: 2 << 30,
	}

	spp = &Spec{
		Name: "ppt", Display: "PowerPoint presentation (OLE)", Ext: ".ppt",
		Header:   cfbSig,
		Length:   cfbLength,
		Validate: cfbFamilyIs("ppt"),
		MinSize:  512, MaxSize: 2 << 30,
	}

	sole = &Spec{
		Name: "ole", Display: "OLE compound file", Ext: ".ole",
		Header:        cfbSig,
		Length:        cfbLength,
		Validate:      cfbUnknownFamily,
		LowConfidence: true,
		MinSize:       512, MaxSize: 2 << 30,
	}

	// RAR: v4 and v5 signatures share the "Rar!\x1A\x07" prefix; the block
	// walker finds the ENDARC record that terminates the archive.
	srar = &Spec{
		Name: "rar", Display: "RAR archive", Ext: ".rar",
		Header:   []byte{'R', 'a', 'r', '!'},
		Length:   rarLength,
		Validate: rarOK,
		MinSize:  32, MaxSize: 8 << 30,
	}

	// 7z: the end of the archive is reached via the declared next-header
	// offset and size in the start header.
	ssz = &Spec{
		Name: "7z", Display: "7-Zip archive", Ext: ".7z",
		Header:   []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C},
		Length:   szLength,
		Validate: szOK,
		MinSize:  32, MaxSize: 8 << 30,
	}

	// TAR: "ustar" at offset 257; the header checksum separates real entries
	// from the same five bytes occurring in random data.
	star = &Spec{
		Name: "tar", Display: "TAR archive", Ext: ".tar",
		Header:     []byte{'u', 's', 't', 'a', 'r'},
		StartDelta: -257,
		Length:     tarLength,
		Validate:   tarOK,
		MinSize:    512, MaxSize: 8 << 30,
	}

	// gzip: the only way to know the extent of a DEFLATE stream is to inflate
	// it; the length function does exactly that, bounded by gzipMaxOut.
	sgzip = &Spec{
		Name: "gzip", Display: "gzip stream", Ext: ".gz",
		Header:  []byte{0x1F, 0x8B, 0x08},
		Length:  gzipLength,
		MinSize: 18, MaxSize: 1 << 30,
	}

	// bzip2: terminated by the end-of-stream block magic plus its CRC.
	sbzip2 = &Spec{
		Name: "bzip2", Display: "bzip2 stream", Ext: ".bz2",
		Header:    []byte{'B', 'Z', 'h'},
		Footer:    bzip2FooterMagic,
		FooterEnd: bzip2FooterEnd,
		Validate:  bzip2OK,
		MinSize:   14, MaxSize: 1 << 30,
	}

	// xz: the two-byte "YZ" footer is far too common to trust alone, so
	// FooterOK re-checks the backward size against the header and verifies
	// the footer CRC32.
	sxz = &Spec{
		Name: "xz", Display: "xz stream", Ext: ".xz",
		Header:   xzSig,
		Footer:   []byte{'Y', 'Z'},
		FooterOK: xzFooterOK,
		Validate: xzOK,
		MinSize:  32, MaxSize: 1 << 30,
	}

	// SQLite 3: the page count in the header bounds the database file.
	ssqlite = &Spec{
		Name: "sqlite", Display: "SQLite 3 database", Ext: ".sqlite",
		Header:   []byte("SQLite format 3\x00"),
		Length:   sqliteLength,
		Validate: sqliteOK,
		MinSize:  100, MaxSize: 1 << 30,
	}

	// MP3: ID3v2 tag or a chain of MPEG audio frames.
	semp3 = &Spec{
		Name: "mp3", Display: "MP3 audio", Ext: ".mp3",
		Header:   []byte{'I', 'D', '3'},
		Length:   mp3Length,
		Validate: mp3OK,
		MinSize:  32, MaxSize: 512 << 20,
	}

	// MPEG audio without an ID3 tag: the second-frame check separates a real
	// frame-sync chain from the same 11 bits appearing in random data.
	smpegaudio = &Spec{
		Name: "mpeg-audio", Display: "MPEG audio", Ext: ".mpa",
		Header:   []byte{0xFF, 0xFB},
		Length:   mpegAudioLength,
		Validate: mpegAudioOK,
		MinSize:  32, MaxSize: 512 << 20,
	}

	// FLAC: metadata block chain terminated by the last-block flag.
	sflac = &Spec{
		Name: "flac", Display: "FLAC audio", Ext: ".flac",
		Header:   []byte{'f', 'L', 'a', 'C'},
		Length:   flacLength,
		Validate: flacOK,
		MinSize:  42, MaxSize: 512 << 20,
	}

	// AAC: ADTS frame chain; each frame's length field points at the next.
	saac = &Spec{
		Name: "aac", Display: "AAC audio (ADTS)", Ext: ".aac",
		Header:   []byte{0xFF, 0xF1},
		Length:   aacLength,
		Validate: aacOK,
		MinSize:  16, MaxSize: 512 << 20,
	}

	// Matroska/WebM: EBML header followed by a Segment element.
	smkv = &Spec{
		Name: "mkv", Display: "Matroska/WebM video", Ext: ".mkv",
		Header:   []byte{0x1A, 0x45, 0xDF, 0xA3},
		Length:   mkvLength,
		Validate: mkvOK,
		MinSize:  32, MaxSize: 8 << 30,
	}

	// ELF: section/program header tables plus section file extents bound the
	// object; NOBITS sections contribute nothing on disk.
	self = &Spec{
		Name: "elf", Display: "ELF binary", Ext: ".elf",
		Header:   []byte{0x7F, 'E', 'L', 'F'},
		Length:   elfLength,
		Validate: elfOK,
		MinSize:  52, MaxSize: 4 << 30,
	}

	// PE: MZ stub plus a PE signature at e_lfanew. Registered before mz so a
	// real executable is never reported as the bare-DOS fallback.
	spe = &Spec{
		Name: "pe", Display: "PE executable", Ext: ".exe",
		Header:   []byte{'M', 'Z'},
		Length:   peLength,
		Validate: peOK,
		MinSize:  128, MaxSize: 4 << 30,
	}

	// MZ without a PE header: a DOS executable. The size comes from the
	// e_cp/e_cblp page fields, which are frequently stale, so the match is
	// marked low-confidence.
	smz = &Spec{
		Name: "mz", Display: "DOS MZ executable", Ext: ".exe",
		Header:        []byte{'M', 'Z'},
		Length:        mzLength,
		Validate:      mzOK,
		LowConfidence: true,
		MinSize:       512, MaxSize: 64 << 20,
	}
)

// cfbFamilyIs builds a validator that accepts only a CFB container whose root
// directory names the given document family.
func cfbFamilyIs(family string) ValidateFunc {
	return func(s Stream, start int64) bool {
		return cfbFamily(s, start) == family
	}
}

// cfbUnknownFamily accepts any structurally valid CFB whose root directory
// does not resolve to a known office family. It backs the low-confidence ole
// catch-all.
func cfbUnknownFamily(s Stream, start int64) bool {
	if _, _, ok := cfbLength(s, start); !ok {
		return false
	}
	return cfbFamily(s, start) == ""
}
