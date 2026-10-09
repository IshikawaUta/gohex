// Package image opens forensic and virtual-machine disk images and exposes
// them as a plain random-access byte range, so the rest of GoHex (internal/disk,
// internal/fs, the hex view) can treat them exactly like a raw file.
//
// Nothing in this package ever writes to the source image; every reader is
// strictly read-only.
//
// Supported container formats:
//
//   - raw                     byte-for-byte dump, read directly
//   - EWF/E01, L01            Expert Witness Compression Format, multi-segment
//     and logical evidence sets (read natively)
//   - VPC/VHD                 fixed and dynamic Microsoft VHD (read natively)
//   - QCOW2, VMDK, VHDX       delegated to qemu-img, which flattens the image
//     into a temporary raw file for the lifetime of the reader
//
// Format detection is magic-based (never extension-based), so a mislabelled
// file still opens correctly.
package image

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Container format identifiers returned by Reader.Format.
const (
	FormatRaw   = "raw"
	FormatEWF   = "ewf"
	FormatL01   = "l01"
	FormatVHD   = "vhd"
	FormatQCOW2 = "qcow2"
	FormatVMDK  = "vmdk"
	FormatVHDX  = "vhdx"
)

// Reader is a read-only, random-access view of a disk image.
type Reader interface {
	// Size is the logical (virtual) size of the imaged medium in bytes.
	Size() int64

	// ReadAt reads len(p) bytes starting at off. It returns io.EOF when the
	// read runs past the end of the medium.
	ReadAt(p []byte, off int64) (int, error)

	// Format is one of the Format* constants.
	Format() string

	// Close releases the file handle and any temporary artefacts.
	Close() error
}

// Open opens path, detects its container format from magic bytes and returns
// a read-only Reader.
func Open(path string) (Reader, error) {
	return open(path, "")
}

// OpenFormat opens path forcing the given container format
// (FormatRaw, FormatEWF, ...). It skips magic detection, which is useful for
// probing deliberately-corrupt files.
func OpenFormat(path, format string) (Reader, error) {
	if format == "" {
		return nil, fmt.Errorf("image: empty format")
	}
	return open(path, format)
}

func open(path, forced string) (Reader, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("image: %w", err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("image: %s is a directory", path)
	}
	format := forced
	if format == "" {
		head, err := readHead(path)
		if err != nil {
			return nil, fmt.Errorf("image: read header: %w", err)
		}
		format, err = detect(head, path)
		if err != nil {
			return nil, err
		}
	}
	switch format {
	case FormatRaw:
		return openRaw(path)
	case FormatEWF, FormatL01:
		return openEWF(path)
	case FormatVHD:
		return openVHD(path)
	case FormatQCOW2, FormatVMDK, FormatVHDX:
		return openQemu(path, format)
	}
	return nil, fmt.Errorf("image: unknown format %q", format)
}

// readHead returns up to the first 512 bytes of path.
func readHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:n], nil
}

// detect maps leading bytes onto a container format.
func detect(head []byte, path string) (string, error) {
	need := func(n int) bool { return len(head) >= n }
	switch {
	case need(8) && string(head[:8]) == "EVF\x09\r\n\xff\x00":
		return FormatEWF, nil
	case need(8) && string(head[:8]) == "EVF2\r\n\x81\x00":
		return "", fmt.Errorf("image: EWF2 (Ex01) not yet supported")
	case need(8) && (string(head[:8]) == "LVF\x09\r\n\xff\x00" || string(head[:8]) == "MVF\x09\r\n\xff\x00"):
		return FormatL01, nil
	case need(4) && string(head[:4]) == "QFI\xfb":
		return FormatQCOW2, nil
	case need(4) && string(head[:4]) == "KDMV":
		return FormatVMDK, nil
	case need(21) && string(head[:21]) == "# Disk DescriptorFile":
		return FormatVMDK, nil
	case need(8) && string(head[:8]) == "vhdxfile":
		return FormatVHDX, nil
	case need(8) && string(head[:8]) == "conectix":
		return FormatVHD, nil
	case need(8) && string(head[:8]) == "cxsparse":
		return FormatVHD, nil
	}
	// A trailing footer is the only clue a fixed VHD whose payload begins
	// with arbitrary bytes gives away (the qemu writer omits the leading one).
	if tail, err := readTail(path, vhdFooterSize); err == nil && len(tail) == vhdFooterSize {
		if string(tail[:8]) == vhdCookie {
			return FormatVHD, nil
		}
	}
	return FormatRaw, nil
}

// readTail returns up to the last n bytes of path.
func readTail(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() < n {
		return nil, fmt.Errorf("file smaller than %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, st.Size()-n); err != nil {
		return nil, err
	}
	return buf, nil
}

// readAtFull fills p from r at off, returning an error on a short read.
func readAtFull(r io.ReaderAt, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if err == nil {
		err = io.EOF
	}
	return err
}
