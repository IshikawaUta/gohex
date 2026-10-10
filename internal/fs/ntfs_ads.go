package fs

import (
	"fmt"
	"io"
	"strings"
)

// Stream describes one named alternate data stream (ADS) of an NTFS
// file. The unnamed default stream is NOT listed here — it is the
// file itself, already exposed by Stat/ReadAt.
type Stream struct {
	// Name is the stream name without the colon prefix
	// ("secret" for "file.txt:secret").
	Name string `json:"name"`
	// Path is the full reference for UI display ("file.txt:secret").
	Path string `json:"path"`
	// Size is the logical stream size in bytes.
	Size int64 `json:"size"`
	// Resident marks streams whose data lives inside the MFT record.
	Resident bool `json:"resident,omitempty"`
	// Compressed / Encrypted flag the attribute header bits; such
	// streams are listed but not readable by this reader.
	Compressed bool `json:"compressed,omitempty"`
	Encrypted  bool `json:"encrypted,omitempty"`
}

// ADSProvider is an optional filesystem capability: enumerating and
// reading named alternate streams. NTFS implements it; other
// filesystems do not (type-assert to discover).
type ADSProvider interface {
	// AlternateStreams lists the named $DATA streams of the file at
	// path. Directories yield ErrIsDir; unknown paths ErrNotFound.
	AlternateStreams(path string) ([]Stream, error)
	// ReadStreamAt fills p with stream-name data of the file at path
	// starting at off, following io.ReaderAt semantics.
	ReadStreamAt(path, name string, off int64, p []byte) (int, error)
}

// ADSStreams type-asserts f to ADSProvider and lists the alternate
// streams of path. ok is false when the filesystem has no ADS concept.
func ADSStreams(f FS, path string) (streams []Stream, ok bool, err error) {
	p, is := f.(ADSProvider)
	if !is {
		return nil, false, nil
	}
	s, err := p.AlternateStreams(path)
	return s, true, err
}

// ADSReadAt type-asserts f to ADSProvider and reads one named stream.
func ADSReadAt(f FS, path, name string, off int64, p []byte) (int, error) {
	pv, is := f.(ADSProvider)
	if !is {
		return 0, fmt.Errorf("fs: filesystem has no alternate streams")
	}
	return pv.ReadStreamAt(path, name, off, p)
}

// AlternateStreams lists the named $DATA attributes of the resolved
// file record. Only named streams are returned; the unnamed stream is
// the file body itself.
func (n *ntfsFS) AlternateStreams(path string) ([]Stream, error) {
	comps := splitPath(path)
	if len(comps) == 0 {
		return nil, ErrIsDir
	}
	_, r, err := n.resolve(comps)
	if err != nil {
		return nil, err
	}
	if r.isDir() {
		return nil, ErrIsDir
	}
	return streamsOf(r, comps[len(comps)-1]), nil
}

// streamsOf extracts the named $DATA streams of a parsed record.
// base is the file's display name used for the Path field.
func streamsOf(r *ntfsRecord, base string) []Stream {
	out := []Stream{}
	for _, a := range r.attrs {
		if a.typ != ntfsAttrData || a.name == "" {
			continue
		}
		// Skip internal system streams like "$DATA:$Secure:$SDS".
		if strings.HasPrefix(a.name, "$") {
			continue
		}
		size := a.realSize
		if a.resident {
			size = int64(len(a.content))
		}
		out = append(out, Stream{
			Name:       a.name,
			Path:       base + ":" + a.name,
			Size:       size,
			Resident:   a.resident,
			Compressed: a.flags&ntfsAttrCompressed != 0,
			Encrypted:  a.flags&ntfsAttrEncrypted != 0,
		})
	}
	return out
}

// ReadStreamAt reads from the named $DATA attribute of the resolved
// file record. Compressed/encrypted streams are rejected; the caller
// must check Stream.Compressed/Encrypted before offering to read.
func (n *ntfsFS) ReadStreamAt(path, name string, off int64, p []byte) (int, error) {
	if name == "" {
		return 0, fmt.Errorf("fs/ntfs: stream name must be non-empty (use ReadAt for the default stream)")
	}
	comps := splitPath(path)
	_, r, err := n.resolve(comps)
	if err != nil {
		return 0, err
	}
	a := findAttrIn(r.attrs, ntfsAttrData, name)
	if a == nil {
		return 0, ErrNotFound
	}
	return readStreamAttr(n, a, off, p)
}

// readStreamAttr reads from one $DATA attribute (named or unnamed).
func readStreamAttr(n *ntfsFS, a *ntfsAttr, off int64, p []byte) (int, error) {
	if a.flags&ntfsAttrCompressed != 0 || a.flags&ntfsAttrEncrypted != 0 {
		return 0, fmt.Errorf("fs/ntfs: compressed/encrypted stream not supported")
	}
	size := a.realSize
	if a.resident {
		size = int64(len(a.content))
	}
	if off < 0 {
		return 0, fmt.Errorf("fs/ntfs: negative offset")
	}
	if off >= size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > size-off {
		want = int(size - off)
	}
	if a.resident {
		copy(p, a.content[off:off+int64(want)])
	} else {
		runs, rerr := n.decodeRuns(a)
		if rerr != nil {
			return 0, rerr
		}
		buf := make([]byte, want)
		if err := n.readRunsAt(buf, runs, off); err != nil {
			return 0, err
		}
		copy(p, buf)
	}
	if want < len(p) {
		return want, io.EOF
	}
	return want, nil
}
