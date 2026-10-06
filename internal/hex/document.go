// Package hex implements the GoHex editing engine: a span-overlay document
// model that can open files of arbitrary size without loading them into
// memory, structural edit operations with unlimited undo/redo, and a search
// engine supporting hex, text, wildcard and regular-expression patterns.
package hex

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/IshikawaUta/gohex/internal/core"
)

type spanKind uint8

const (
	// spanBase references a range of the original read-only source.
	spanBase spanKind = iota
	// spanData holds edited bytes owned by the document.
	spanData
)

// span is one contiguous piece of the logical document. The logical byte
// stream is the ordered concatenation of all spans. Base spans point into the
// original source (so a 64 GiB file costs no RAM), data spans hold bytes the
// user typed (so memory is bounded by the size of the edits themselves).
type span struct {
	kind   spanKind
	base   int64 // start offset in the original source (spanBase)
	data   []byte
	length int64
}

func (s span) suffix(off int64) span {
	if s.kind == spanBase {
		return span{kind: spanBase, base: s.base + off, length: s.length - off}
	}
	return span{kind: spanData, data: s.data[off:], length: s.length - off}
}

func (s span) prefix(n int64) span {
	if s.kind == spanBase {
		return span{kind: spanBase, base: s.base, length: n}
	}
	return span{kind: spanData, data: s.data[:n], length: n}
}

// journalEntry records one edit so it can be inverted. Undo restores
// removed bytes; redo restores inserted bytes. Both payloads are the only
// memory cost of the history — the base file is never copied.
type journalEntry struct {
	off      int64
	removed  []byte
	inserted []byte
	label    string
	// beforeID/afterID identify the content states on either side of this
	// edit so Dirty can tell whether the current state equals the saved one.
	beforeID uint64
	afterID  uint64
}

// Document is a mutable, random-access byte stream backed by an optional
// read-only source. All methods are safe for concurrent use.
type Document struct {
	mu     sync.RWMutex
	src    core.Source
	closed bool
	spans  []span
	// starts[i] is the logical offset where spans[i] begins; starts has the
	// same length as spans and starts[0] == 0 when spans is non-empty.
	starts []int64
	total  int64

	overwriteOnly bool // true until the first insert/delete
	// Content-state identity graph: every recorded edit gets a fresh unique
	// id; undo/redo jump to the id stored in the journal entry. The document
	// is dirty exactly when the current id differs from the saved one, so
	// undoing all the way back to the last save (or to the opened state)
	// marks the document clean again — matching what editors users expect.
	stateID uint64
	savedID uint64
	idSeq   uint64
	version uint64

	// dirtyRanges tracks overwritten regions that differ from the source so
	// Save can write back in place without rewriting the whole file.
	// fullDirty means the layout changed (insert/delete) and a full rewrite
	// is required.
	dirtyRanges []DirtyRange
	fullDirty   bool

	undoStack []journalEntry
	redoStack []journalEntry
}

// New creates a Document backed by src. The source stays open and read-only
// for the lifetime of the document; Close does not close the source.
func New(src core.Source) *Document {
	d := &Document{src: src, overwriteOnly: true}
	if src != nil && src.Size() > 0 {
		d.spans = []span{{kind: spanBase, base: 0, length: src.Size()}}
		d.total = src.Size()
	}
	d.rebuildIndex()
	return d
}

// NewEmpty creates a zero-length document with no backing source, used for
// "new file" and paste buffers.
func NewEmpty() *Document {
	return New(nil)
}

// DirtyRange is a region of the logical document that differs from the
// backing source.
type DirtyRange struct {
	Start  int64 `json:"start"`
	Length int64 `json:"length"`
}

// maxDirtyRanges caps range-tracking memory; beyond it Save falls back to a
// full rewrite (still correct, just less optimal).
const maxDirtyRanges = 8192

// ErrClosed is returned when operating on a closed document.
var ErrClosed = errors.New("hex: document is closed")

// Close releases document resources. The underlying source is left open for
// the caller (the service layer owns source lifetime).
func (d *Document) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	d.spans = nil
	d.starts = nil
	d.total = 0
	return nil
}

// Size returns the logical size: the size the file would have if saved right
// now (base size adjusted for inserts and deletes).
func (d *Document) Size() int64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.total
}

// BaseSize returns the size of the original source (0 for empty documents).
func (d *Document) BaseSize() int64 {
	if d.src == nil {
		return 0
	}
	return d.src.Size()
}

// Source returns the backing read-only source, or nil.
func (d *Document) Source() core.Source { return d.src }

// Path returns the source name if any (for display and Save).
func (d *Document) Path() string {
	if d.src == nil {
		return ""
	}
	return d.src.Name()
}

// Dirty reports unsaved changes: true when the current content state is not
// the one that was last saved (or opened).
func (d *Document) Dirty() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.stateID != d.savedID
}

// Version increments on every mutation; the GUI uses it to invalidate cached
// rendered rows cheaply.
func (d *Document) Version() uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.version
}

// OverwriteOnly reports whether every edit so far was an in-place overwrite,
// i.e. whether Save can be performed by writing directly at base offsets
// without rewriting the file.
func (d *Document) OverwriteOnly() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.overwriteOnly
}

// ReadAt implements io.ReaderAt over the logical document.
func (d *Document) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, core.ErrNegativeOffset
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.readAtLocked(p, off)
}

func (d *Document) readAtLocked(p []byte, off int64) (int, error) {
	if d.closed {
		return 0, ErrClosed
	}
	if off >= d.total {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && off+int64(n) < d.total {
		i := d.spanIndexLocked(off + int64(n))
		if i < 0 {
			break
		}
		s := d.spans[i]
		local := (off + int64(n)) - d.starts[i]
		avail := s.length - local
		take := int64(len(p) - n)
		if take > avail {
			take = avail
		}
		switch s.kind {
		case spanBase:
			got, err := d.src.ReadAt(p[n:n+int(take)], s.base+local)
			n += got
			if err != nil && err != io.EOF {
				return n, err
			}
		case spanData:
			n += copy(p[n:n+int(take)], s.data[local:local+take])
		}
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// ReadCopy materialises n bytes starting at logical offset off.
func (d *Document) ReadCopy(off, n int64) ([]byte, error) {
	if off < 0 || n < 0 {
		return nil, core.ErrNegativeOffset
	}
	if n == 0 {
		return []byte{}, nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if off >= d.total {
		return nil, core.ErrOutOfBounds
	}
	if off+n > d.total {
		n = d.total - off
	}
	buf := make([]byte, n)
	got, err := d.readAtLocked(buf, off)
	if got > 0 && (err == nil || err == io.EOF) {
		return buf[:got], nil
	}
	if err == nil {
		err = io.EOF
	}
	return nil, fmt.Errorf("hex: read %#x+%#x: %w", off, n, err)
}

// spanIndexLocked returns the index of the span containing logical offset off,
// or -1 when off is at/past the end.
func (d *Document) spanIndexLocked(off int64) int {
	if len(d.spans) == 0 || off >= d.total || off < 0 {
		return -1
	}
	i := sort.Search(len(d.starts), func(i int) bool { return d.starts[i] > off }) - 1
	if i < 0 {
		return 0
	}
	return i
}

// splitAtLocked guarantees a span boundary at logical offset off, returning
// the index of the span that starts exactly at off (len(spans) when off is at
// the end). It is the building block of every structural edit.
func (d *Document) splitAtLocked(off int64) int {
	if off <= 0 {
		return 0
	}
	if off >= d.total {
		return len(d.spans)
	}
	i := d.spanIndexLocked(off)
	local := off - d.starts[i]
	if local == 0 {
		return i
	}
	s := d.spans[i]
	left := s.prefix(local)
	right := s.suffix(local)
	d.spans = append(d.spans, span{})
	copy(d.spans[i+2:], d.spans[i+1:])
	d.spans[i] = left
	d.spans[i+1] = right
	d.rebuildIndex()
	return i + 1
}

func (d *Document) rebuildIndex() {
	d.starts = make([]int64, len(d.spans))
	var off int64
	for i, s := range d.spans {
		d.starts[i] = off
		off += s.length
	}
	d.total = off
}

// DirtyState reports how the document differs from its saved/base state:
// the list of overwritten ranges and whether a full rewrite is needed.
func (d *Document) DirtyState() ([]DirtyRange, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return append([]DirtyRange(nil), d.dirtyRanges...), d.fullDirty
}

// addDirtyLocked records a change of logical length n at off (insert/delete
// with differing sizes escalate to a full rewrite).
func (d *Document) addDirtyLocked(off, n, insLen int64) {
	if n == 0 && insLen == 0 {
		return
	}
	if n != insLen {
		d.fullDirty = true
		d.dirtyRanges = nil
		return
	}
	if d.fullDirty {
		return
	}
	nr := DirtyRange{Start: off, Length: n}
	// Merge with any overlapping or adjacent range; escalate if the list
	// exceeds the cap (correctness first — a full rewrite is still fine).
	for i := 0; i < len(d.dirtyRanges); i++ {
		r := d.dirtyRanges[i]
		if nr.Start <= r.Start+r.Length && r.Start <= nr.Start+nr.Length {
			if r.Start < nr.Start {
				nr.Start = r.Start
			}
			if r.Start+r.Length > nr.Start+nr.Length {
				nr.Length = r.Start + r.Length - nr.Start
			}
			d.dirtyRanges = append(d.dirtyRanges[:i], d.dirtyRanges[i+1:]...)
			i--
		}
	}
	d.dirtyRanges = append(d.dirtyRanges, nr)
	if len(d.dirtyRanges) > maxDirtyRanges {
		d.fullDirty = true
		d.dirtyRanges = nil
	}
}
