package recovery

import (
	"errors"
	"fmt"
	"io"
)

// Extract copies the carved range c out of s into w and returns the number of
// bytes written. The source is only ever read.
func Extract(s Stream, c Carved, w io.Writer) (int64, error) {
	if s == nil {
		return 0, errors.New("recovery: nil stream")
	}
	if w == nil {
		return 0, errors.New("recovery: nil writer")
	}
	if c.Offset < 0 || c.Length < 0 {
		return 0, fmt.Errorf("recovery: invalid range %#x+%#x", c.Offset, c.Length)
	}
	end := c.Offset + c.Length
	if end < c.Offset || end > s.Size() {
		return 0, fmt.Errorf("recovery: range %#x+%#x exceeds source size %#x", c.Offset, c.Length, s.Size())
	}
	if c.Length == 0 {
		return 0, nil
	}
	buf := make([]byte, copyChunk)
	var done int64
	for done < c.Length {
		n := int64(len(buf))
		if remaining := c.Length - done; remaining < n {
			n = remaining
		}
		if err := readFullAt(s, buf[:n], c.Offset+done); err != nil {
			return done, fmt.Errorf("recovery: read at %#x: %w", c.Offset+done, err)
		}
		written, err := w.Write(buf[:n])
		done += int64(written)
		if err != nil {
			return done, fmt.Errorf("recovery: write: %w", err)
		}
		if int64(written) < n {
			return done, io.ErrShortWrite
		}
	}
	return done, nil
}
