package recovery

// registry holds every carveable type in display order. Specs are package-level
// values: the scanner never mutates them, so sharing pointers is safe.
var registry = []*Spec{
	sjpeg, spng, sgif, spdf, szip, sbmp, swav, savi, smp4,
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
)
