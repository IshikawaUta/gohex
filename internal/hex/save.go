package hex

import (
	"fmt"
	"io"
)

// WriteTo streams the entire logical document to w in bounded 1 MiB chunks so
// that even multi-gigabyte images are written with constant memory. It
// implements io.WriterTo.
func (d *Document) WriteTo(w io.Writer) (int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.writeToLocked(w)
}

func (d *Document) writeToLocked(w io.Writer) (int64, error) {
	if d.closed {
		return 0, ErrClosed
	}
	const chunk = 1 << 20
	buf := make([]byte, chunk)
	var off int64
	for off < d.total {
		n := int64(chunk)
		if off+n > d.total {
			n = d.total - off
		}
		got, err := d.readAtLocked(buf[:n], off)
		if got > 0 {
			wrote, werr := w.Write(buf[:got])
			off += int64(wrote)
			if werr != nil {
				return off, fmt.Errorf("hex: stream write: %w", werr)
			}
		}
		if err != nil && err != io.EOF {
			return off, fmt.Errorf("hex: stream read at %#x: %w", off, err)
		}
		if got == 0 {
			return off, fmt.Errorf("hex: stream stalled at %#x", off)
		}
	}
	return off, nil
}
