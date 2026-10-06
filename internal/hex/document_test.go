package hex

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/IshikawaUta/gohex/internal/core"
)

func newDocFrom(t *testing.T, data []byte) *Document {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := core.OpenFile(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	return New(src)
}

func TestDocumentReadBasics(t *testing.T) {
	data := []byte("The quick brown fox")
	d := newDocFrom(t, data)
	if d.Size() != int64(len(data)) || d.BaseSize() != int64(len(data)) {
		t.Fatalf("size=%d base=%d", d.Size(), d.BaseSize())
	}
	if d.Path() == "" {
		t.Fatal("path empty")
	}
	if d.Dirty() || !d.OverwriteOnly() {
		t.Fatal("new doc should be clean & overwrite-only")
	}
	got, err := d.ReadCopy(4, 5)
	if err != nil || string(got) != "quick" {
		t.Fatalf("ReadCopy = %q, %v", got, err)
	}
	buf := make([]byte, 10)
	if n, err := d.ReadAt(buf, int64(len(data))-3); n != 3 || err != io.EOF {
		t.Fatalf("tail ReadAt n=%d err=%v", n, err)
	}
	if _, err := d.ReadCopy(int64(len(data)), 1); err == nil {
		t.Fatal("read past end should fail")
	}
	if _, err := d.ReadCopy(-1, 1); err == nil {
		t.Fatal("negative read should fail")
	}
	got, err = d.ReadCopy(0, 0)
	if err != nil || len(got) != 0 {
		t.Fatalf("zero read = %v, %v", got, err)
	}
}

func TestOverwriteInsertDeleteFill(t *testing.T) {
	d := newDocFrom(t, []byte("HELLO WORLD"))

	if err := d.Overwrite(0, []byte("J")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.WriteAt([]byte("E"), 1); err != nil {
		t.Fatal(err)
	}
	got, _ := d.ReadCopy(0, 11)
	if string(got) != "JELLO WORLD" {
		t.Fatalf("after overwrite = %q", got)
	}

	// Insert grows the document.
	if err := d.Insert(5, []byte(",_HI,")); err != nil {
		t.Fatal(err)
	}
	if d.Size() != 16 || d.OverwriteOnly() {
		t.Fatalf("size=%d overwriteOnly=%v", d.Size(), d.OverwriteOnly())
	}
	got, _ = d.ReadCopy(0, 16)
	if string(got) != "JELLO,_HI, WORLD" {
		t.Fatalf("after insert = %q (len %d)", got, len(got))
	}

	// Delete shrinks.
	if err := d.Delete(5, 5); err != nil {
		t.Fatal(err)
	}
	got, _ = d.ReadCopy(0, d.Size())
	if string(got) != "JELLO WORLD" {
		t.Fatalf("after delete = %q", got)
	}

	// Fill.
	if err := d.Fill(0, 5, 'X'); err != nil {
		t.Fatal(err)
	}
	got, _ = d.ReadCopy(0, d.Size())
	if string(got) != "XXXXX WORLD" {
		t.Fatalf("after fill = %q", got)
	}

	// Bounds errors.
	if err := d.Overwrite(d.Size(), []byte("Z")); err == nil {
		t.Fatal("overwrite past end must fail")
	}
	if err := d.Delete(d.Size(), 1); err == nil {
		t.Fatal("delete past end must fail")
	}
	if err := d.Insert(-1, []byte("Z")); err == nil {
		t.Fatal("negative insert must fail")
	}
	// No-op edits.
	if err := d.Overwrite(0, nil); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(0, 0); err != nil {
		t.Fatal(err)
	}
	if err := d.Insert(0, nil); err != nil {
		t.Fatal(err)
	}
	if err := d.Fill(0, 0, 0); err != nil {
		t.Fatal(err)
	}
}

func TestUndoRedo(t *testing.T) {
	d := newDocFrom(t, []byte("ABCDEFGH"))
	var err error

	if err = d.Overwrite(0, []byte("11")); err != nil {
		t.Fatal(err)
	}
	if err = d.Insert(2, []byte("XX")); err != nil {
		t.Fatal(err)
	}
	if err = d.Delete(0, 1); err != nil {
		t.Fatal(err)
	}
	got, _ := d.ReadCopy(0, d.Size())
	want := "1XXCDEFGH" // overwrite → insert → delete first byte
	if string(got) != want {
		t.Fatalf("state = %q want %q", got, want)
	}

	undo, redo := d.HistoryLen()
	if undo != 3 || redo != 0 {
		t.Fatalf("history = %d/%d", undo, redo)
	}

	// Undo everything.
	for i := 0; i < 3; i++ {
		if _, err := d.Undo(); err != nil {
			t.Fatalf("undo %d: %v", i, err)
		}
	}
	got, _ = d.ReadCopy(0, d.Size())
	if string(got) != "ABCDEFGH" {
		t.Fatalf("after undo = %q", got)
	}
	if _, err := d.Undo(); err == nil {
		t.Fatal("undo on empty stack must fail")
	}
	if _, ok := d.CanUndo(); ok {
		t.Fatal("CanUndo on empty stack")
	}

	// Redo everything.
	for i := 0; i < 3; i++ {
		if _, err := d.Redo(); err != nil {
			t.Fatalf("redo %d: %v", i, err)
		}
	}
	got, _ = d.ReadCopy(0, d.Size())
	if string(got) != "1XXCDEFGH" {
		t.Fatalf("after redo = %q", got)
	}
	if _, err := d.Redo(); err == nil {
		t.Fatal("redo on empty stack must fail")
	}

	// A new edit clears the redo stack.
	_, _ = d.Undo()
	if _, ok := d.CanRedo(); !ok {
		t.Fatal("redo should be available")
	}
	if err = d.Overwrite(0, []byte("Q")); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.CanRedo(); ok {
		t.Fatal("new edit must clear redo stack")
	}

	// Label reporting.
	if label, ok := d.CanUndo(); !ok || label == "" {
		t.Fatalf("CanUndo label = %q ok=%v", label, ok)
	}
}

func TestWriteToStreamsLogicalContent(t *testing.T) {
	base := bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 300000) // ~2.4 MB spans
	d := newDocFrom(t, base)
	if err := d.Insert(10, []byte("INS")); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(100, 50); err != nil {
		t.Fatal(err)
	}
	if err := d.Overwrite(1000, bytes.Repeat([]byte{0xEE}, 100)); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	n, err := d.WriteTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != d.Size() || int64(buf.Len()) != n {
		t.Fatalf("wrote %d, size %d", n, d.Size())
	}
	// Verify content against an independent buffer-based reconstruction.
	expect := buildExpected(t, base)
	if !bytes.Equal(buf.Bytes(), expect) {
		t.Fatalf("stream mismatch at %d", firstDiff(buf.Bytes(), expect))
	}
}

func buildExpected(t *testing.T, base []byte) []byte {
	t.Helper()
	// Recreate the exact same ops on a plain buffer.
	b := append([]byte{}, base...)
	b = append(b[:10], append([]byte("INS"), b[10:]...)...) // insert at 10
	b = append(b[:100], b[150:]...)                         // delete 50 bytes at 100
	for i := 0; i < 100; i++ {
		b[1000+i] = 0xEE
	}
	return b
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

func TestEmptyDocument(t *testing.T) {
	d := NewEmpty()
	if d.Size() != 0 || d.Path() != "" || d.BaseSize() != 0 {
		t.Fatal("empty doc metadata")
	}
	if err := d.Insert(0, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if d.Size() != 0 {
		t.Fatal("closed doc size")
	}
	if _, err := d.WriteTo(io.Discard); err == nil {
		t.Fatal("closed doc stream should fail")
	}
	if d.Source() != nil {
		t.Fatal("empty doc source")
	}
}

func TestVersionDirtyTracking(t *testing.T) {
	d := newDocFrom(t, []byte("abcd"))
	v0 := d.Version()
	if d.Dirty() {
		t.Fatal("clean on open")
	}
	_ = d.Overwrite(0, []byte("x"))
	if d.Version() == v0 || !d.Dirty() {
		t.Fatal("version/dirty after edit")
	}
	d.MarkSaved()
	if d.Dirty() {
		t.Fatal("MarkSaved")
	}
	d.ResetHistory()
	if u, r := d.HistoryLen(); u != 0 || r != 0 {
		t.Fatal("ResetHistory")
	}
}

func TestDirtyStateIdentity(t *testing.T) {
	d := newDocFrom(t, []byte("abcd"))
	if d.Dirty() {
		t.Fatal("clean on open")
	}
	if err := d.Overwrite(1, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if !d.Dirty() {
		t.Fatal("dirty after edit")
	}
	if _, err := d.Undo(); err != nil {
		t.Fatal(err)
	}
	if d.Dirty() {
		t.Fatal("undo back to opened state should be clean")
	}
	if _, err := d.Redo(); err != nil {
		t.Fatal(err)
	}
	if !d.Dirty() {
		t.Fatal("redo re-applies the edit")
	}
	d.MarkSaved()
	if d.Dirty() {
		t.Fatal("clean after save")
	}
	if _, err := d.Undo(); err != nil {
		t.Fatal(err)
	}
	if !d.Dirty() {
		t.Fatal("undo past the save point should be dirty")
	}
	if _, err := d.Redo(); err != nil {
		t.Fatal(err)
	}
	if d.Dirty() {
		t.Fatal("redo back to the save point should be clean")
	}
	// Diverging edit after undo gets a fresh identity even if the undo
	// depth happens to match a previously saved depth.
	if _, err := d.Undo(); err != nil {
		t.Fatal(err)
	}
	if err := d.Overwrite(2, []byte("y")); err != nil {
		t.Fatal(err)
	}
	if !d.Dirty() {
		t.Fatal("divergent edit is dirty")
	}
}
