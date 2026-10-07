package image

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// qemuReader serves a flattened raw copy produced by qemu-img and removes the
// temporary directory on Close.
type qemuReader struct {
	*rawReader
	format string
	dir    string
}

func (r *qemuReader) Format() string { return r.format }
func (r *qemuReader) Close() error {
	err := r.rawReader.Close()
	os.RemoveAll(r.dir)
	return err
}

// openQemu flattens a qemu-supported image (qcow2, vmdk, vhdx, ...) into a
// temporary raw file and serves reads from there.
//
// This trades disk space for correctness: the temporary file only exists while
// the reader is open and is removed on Close. It also means these formats
// require qemu-img on PATH; Open reports a clear error when it is missing.
func openQemu(path, format string) (Reader, error) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		return nil, fmt.Errorf("image/%s: requires qemu-img on PATH: %w", format, err)
	}
	dir, err := os.MkdirTemp("", "gohex-img-")
	if err != nil {
		return nil, fmt.Errorf("image/%s: %w", format, err)
	}
	rawPath := filepath.Join(dir, "disk.raw")
	out, err := exec.Command("qemu-img", "convert", "-O", "raw", path, rawPath).CombinedOutput()
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("image/%s: qemu-img convert: %v\n%s", format, err, out)
	}
	base, err := openRaw(rawPath)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	return &qemuReader{rawReader: base.(*rawReader), format: format, dir: dir}, nil
}
