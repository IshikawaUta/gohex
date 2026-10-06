package hex

import (
	"fmt"

	"github.com/IshikawaUta/gohex/internal/core"
)

// replaceLocked is the single mutation primitive: it replaces the logical
// range [off, off+n) with data and returns the bytes that were removed.
// When record is true the inverse operation is pushed onto the undo stack.
func (d *Document) replaceLocked(off, n int64, data []byte, record bool, label string) ([]byte, error) {
	if d.closed {
		return nil, ErrClosed
	}
	if off < 0 || n < 0 {
		return nil, core.ErrNegativeOffset
	}
	if off+n > d.total {
		return nil, fmt.Errorf("hex: range [%#x,%#x) exceeds size %#x: %w", off, off+n, d.total, core.ErrOutOfBounds)
	}
	// Materialise the victim bytes before mutating.
	removed := make([]byte, n)
	if n > 0 {
		if _, err := d.readAtLocked(removed, off); err != nil && len(removed) > 0 {
			return nil, err
		}
	}
	startIdx := d.splitAtLocked(off)
	endIdx := d.splitAtLocked(off + n)
	// Drop the covered spans.
	if endIdx > startIdx {
		copy(d.spans[startIdx:], d.spans[endIdx:])
		d.spans = d.spans[:len(d.spans)-(endIdx-startIdx)]
	}
	insLen := int64(0)
	if len(data) > 0 {
		cp := make([]byte, len(data))
		copy(cp, data)
		d.spans = append(d.spans, span{})
		copy(d.spans[startIdx+1:], d.spans[startIdx:])
		d.spans[startIdx] = span{kind: spanData, data: cp, length: int64(len(cp))}
		insLen = int64(len(cp))
	}
	d.rebuildIndex()
	d.version++
	d.addDirtyLocked(off, n, insLen)
	if record {
		d.idSeq++
		entry := journalEntry{
			off: off, removed: removed, inserted: cpData(data), label: label,
			beforeID: d.stateID, afterID: d.idSeq,
		}
		d.stateID = d.idSeq
		d.undoStack = append(d.undoStack, entry)
		d.redoStack = nil
	}
	if n != insLen {
		d.overwriteOnly = false
	}
	return removed, nil
}

func cpData(p []byte) []byte {
	if p == nil {
		return nil
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	return cp
}

// Overwrite writes p at logical offset off, replacing existing bytes without
// changing the document size.
func (d *Document) Overwrite(off int64, p []byte) error {
	if len(p) == 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.replaceLocked(off, int64(len(p)), p, true,
		fmt.Sprintf("Overwrite %d bytes at %s", len(p), core.FormatOffset(off, core.BaseHex, 0)))
	return err
}

// WriteAt implements io.WriterAt as an alias for Overwrite.
func (d *Document) WriteAt(p []byte, off int64) (int, error) {
	if err := d.Overwrite(off, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Insert splices p into the document at off, growing it by len(p).
func (d *Document) Insert(off int64, p []byte) error {
	if len(p) == 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.replaceLocked(off, 0, p, true,
		fmt.Sprintf("Insert %d bytes at %s", len(p), core.FormatOffset(off, core.BaseHex, 0)))
	return err
}

// Delete removes n bytes at off, shrinking the document.
func (d *Document) Delete(off, n int64) error {
	if n == 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.replaceLocked(off, n, nil, true,
		fmt.Sprintf("Delete %d bytes at %s", n, core.FormatOffset(off, core.BaseHex, 0)))
	return err
}

// Fill overwrites [off, off+n) with the byte value b.
func (d *Document) Fill(off, n int64, b byte) error {
	if n == 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	pattern := make([]byte, n)
	for i := range pattern {
		pattern[i] = b
	}
	_, err := d.replaceLocked(off, n, pattern, true,
		fmt.Sprintf("Fill %d bytes at %s with %02X", n, core.FormatOffset(off, core.BaseHex, 0), b))
	return err
}

// Undo reverts the most recent edit. It returns the label of the reverted
// operation so the GUI can report what happened.
func (d *Document) Undo() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.undoStack) == 0 {
		return "", fmt.Errorf("hex: nothing to undo")
	}
	e := d.undoStack[len(d.undoStack)-1]
	d.undoStack = d.undoStack[:len(d.undoStack)-1]
	if _, err := d.replaceLocked(e.off, int64(len(e.inserted)), e.removed, false, ""); err != nil {
		d.undoStack = append(d.undoStack, e)
		return "", fmt.Errorf("hex: undo failed: %w", err)
	}
	d.stateID = e.beforeID
	d.redoStack = append(d.redoStack, e)
	return e.label, nil
}

// Redo re-applies the most recently undone edit.
func (d *Document) Redo() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.redoStack) == 0 {
		return "", fmt.Errorf("hex: nothing to redo")
	}
	e := d.redoStack[len(d.redoStack)-1]
	d.redoStack = d.redoStack[:len(d.redoStack)-1]
	if _, err := d.replaceLocked(e.off, int64(len(e.removed)), e.inserted, false, ""); err != nil {
		d.redoStack = append(d.redoStack, e)
		return "", fmt.Errorf("hex: redo failed: %w", err)
	}
	d.stateID = e.afterID
	d.undoStack = append(d.undoStack, e)
	return e.label, nil
}

// CanUndo returns the label of the operation that Undo would revert.
func (d *Document) CanUndo() (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.undoStack) == 0 {
		return "", false
	}
	return d.undoStack[len(d.undoStack)-1].label, true
}

// CanRedo returns the label of the operation that Redo would re-apply.
func (d *Document) CanRedo() (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.redoStack) == 0 {
		return "", false
	}
	return d.redoStack[len(d.redoStack)-1].label, true
}

// HistoryLen returns the number of undoable and redoable operations.
func (d *Document) HistoryLen() (undo, redo int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.undoStack), len(d.redoStack)
}

// ResetHistory clears undo/redo stacks, e.g. after a successful save.
func (d *Document) ResetHistory() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.undoStack = nil
	d.redoStack = nil
}

// MarkSaved records the current content state as the saved baseline and
// clears range tracking without touching the edit history (call after a
// successful save).
func (d *Document) MarkSaved() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.savedID = d.stateID
	d.dirtyRanges = nil
	d.fullDirty = false
}
