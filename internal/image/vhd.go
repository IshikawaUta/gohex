package image

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// VHD disk types (footer offset 60, big-endian).
const (
	vhdTypeFixed        = 2
	vhdTypeDynamic      = 3
	vhdTypeDifferencing = 4
)

const (
	vhdFooterSize = 512
	vhdCookie     = "conectix"
	vhdDynCookie  = "cxsparse"
)

// vhdReader reads a Microsoft VHD image. Multi-byte VHD fields are
// big-endian (the format predates little-endian-dominant tooling).
type vhdReader struct {
	f      *os.File
	size   int64 // virtual size of the medium
	format string

	fixed     bool
	dataStart int64 // fixed disks: byte offset of the payload

	// dynamic disks
	blockSize int64
	bitmap    int64   // bytes of sector bitmap leading every data block
	bat       []int64 // file offset per block, -1 = unallocated
}

func openVHD(path string) (Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("image/vhd: %w", err)
	}
	fail := func(err error) (Reader, error) {
		f.Close()
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		return fail(fmt.Errorf("image/vhd: %w", err))
	}
	fileSize := st.Size()
	if fileSize < vhdFooterSize {
		return fail(fmt.Errorf("image/vhd: file too small for a VHD footer"))
	}

	footer := make([]byte, vhdFooterSize)
	footerIsLeading := true
	if err := readAtFull(f, footer, 0); err != nil {
		return fail(fmt.Errorf("image/vhd: read footer: %w", err))
	}
	if string(footer[:8]) != vhdCookie {
		footerIsLeading = false
		if err := readAtFull(f, footer, fileSize-vhdFooterSize); err != nil {
			return fail(fmt.Errorf("image/vhd: read trailing footer: %w", err))
		}
		if string(footer[:8]) != vhdCookie {
			return fail(fmt.Errorf("image/vhd: missing %q cookie", vhdCookie))
		}
	}

	diskType := int(binary.BigEndian.Uint32(footer[60:64]))
	v := &vhdReader{f: f, size: int64(binary.BigEndian.Uint64(footer[48:56]))}
	if v.size < 0 {
		return fail(fmt.Errorf("image/vhd: negative virtual size"))
	}

	switch diskType {
	case vhdTypeFixed:
		// Two fixed-disk layouts are in the wild: the Microsoft one (leading
		// footer, payload at 512, trailing footer) and the qemu one (payload
		// at 0, trailing footer only). Decide from the leading cookie.
		v.fixed, v.format = true, FormatVHD
		leadCookie := string(footer[:8]) == vhdCookie && footerIsLeading
		switch {
		case leadCookie:
			v.dataStart = vhdFooterSize
		case fileSize >= v.size+vhdFooterSize:
			v.dataStart = 0
		default:
			return fail(fmt.Errorf("image/vhd: truncated fixed image: have %d, need %d",
				fileSize, v.size+vhdFooterSize))
		}
		if fileSize < v.dataStart+v.size {
			return fail(fmt.Errorf("image/vhd: truncated fixed image: have %d, need %d",
				fileSize, v.dataStart+v.size))
		}
	case vhdTypeDynamic:
		if err := v.loadDynamic(f, footer, fileSize); err != nil {
			return fail(err)
		}
		v.format = FormatVHD
	case vhdTypeDifferencing:
		return fail(fmt.Errorf("image/vhd: differencing VHD needs its parent image (not supported)"))
	default:
		return fail(fmt.Errorf("image/vhd: unknown disk type %d", diskType))
	}
	return v, nil
}

// loadDynamic reads the dynamic header and block allocation table.
func (v *vhdReader) loadDynamic(f *os.File, footer []byte, fileSize int64) error {
	hdrOff := int64(binary.BigEndian.Uint64(footer[16:24]))
	if hdrOff < 0 || hdrOff+vhdFooterSize > fileSize {
		hdrOff = vhdFooterSize // the common "data offset not set" case
	}
	hdr := make([]byte, 1024)
	if err := readAtFull(f, hdr, hdrOff); err != nil {
		return fmt.Errorf("image/vhd: read dynamic header: %w", err)
	}
	if string(hdr[:8]) != vhdDynCookie {
		return fmt.Errorf("image/vhd: missing %q dynamic header cookie", vhdDynCookie)
	}
	batOff := int64(binary.BigEndian.Uint64(hdr[16:24]))
	blockSize := int64(binary.BigEndian.Uint32(hdr[32:36]))
	maxEntries := int64(binary.BigEndian.Uint32(hdr[28:32]))
	if blockSize < 512 || blockSize&(blockSize-1) != 0 {
		return fmt.Errorf("image/vhd: invalid block size %d", blockSize)
	}
	// Every allocated block is a sector bitmap followed by the payload:
	// one bit per 512-byte sector of the block, rounded up to a sector.
	bitmap := ((blockSize/4096 + 511) / 512) * 512
	if bitmap < 512 {
		bitmap = 512
	}
	blocks := (v.size + blockSize - 1) / blockSize
	if blocks <= 0 || blocks > maxEntries {
		return fmt.Errorf("image/vhd: block count %d exceeds table entries %d", blocks, maxEntries)
	}
	raw := make([]byte, blocks*4)
	if batOff < 0 || batOff+int64(len(raw)) > fileSize {
		return fmt.Errorf("image/vhd: block allocation table beyond end of file")
	}
	if err := readAtFull(f, raw, batOff); err != nil {
		return fmt.Errorf("image/vhd: read allocation table: %w", err)
	}
	v.blockSize = blockSize
	v.bitmap = bitmap
	v.bat = make([]int64, blocks)
	for i := range v.bat {
		e := binary.BigEndian.Uint32(raw[i*4:])
		if e == 0xFFFFFFFF {
			v.bat[i] = -1
			continue
		}
		off := int64(e) * 512
		if off < 0 || off+bitmap > fileSize {
			return fmt.Errorf("image/vhd: block %d points outside the file", i)
		}
		v.bat[i] = off
	}
	return nil
}

func (v *vhdReader) Size() int64    { return v.size }
func (v *vhdReader) Format() string { return v.format }
func (v *vhdReader) Close() error   { return v.f.Close() }

func (v *vhdReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if off >= v.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > v.size-off {
		want = int(v.size - off)
	}
	filled := 0
	for filled < want {
		abs := off + int64(filled)
		if v.fixed {
			n, err := v.f.ReadAt(p[filled:want], v.dataStart+abs)
			filled += n
			if err != nil && filled < want {
				return filled, err
			}
			if filled < want {
				return filled, io.EOF
			}
			break
		}
		block := abs / v.blockSize
		inBlock := abs % v.blockSize
		n := int(v.blockSize - inBlock)
		if n > want-filled {
			n = want - filled
		}
		if v.bat[block] < 0 {
			for k := 0; k < n; k++ {
				p[filled+k] = 0
			}
			filled += n
			continue
		}
		if err := readAtFull(v.f, p[filled:filled+n], v.bat[block]+v.bitmap+inBlock); err != nil {
			return filled, fmt.Errorf("image/vhd: read block %d: %w", block, err)
		}
		filled += n
	}
	if filled < len(p) {
		return filled, io.EOF
	}
	return filled, nil
}
