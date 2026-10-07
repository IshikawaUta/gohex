package fs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// mkiso builds an ISO image from a source directory tree.
func mkiso(t *testing.T, args ...string) []byte {
	t.Helper()
	requireTool(t, "genisoimage")
	p := filepath.Join(t.TempDir(), "disc.iso")
	full := append([]string{"-quiet", "-o", p}, args...)
	runCmd(t, "genisoimage", full...)
	img, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// isoSrcDir builds a small source tree for ISO generation.
func isoSrcDir(t *testing.T) (dir string, files map[string][]byte) {
	t.Helper()
	dir = t.TempDir()
	files = map[string][]byte{
		"hello.txt":   []byte("Hello ISO world!\n"),
		"sub/note.md": []byte("# note\nbody\n"),
	}
	writeTempFile(t, dir, "hello.txt", files["hello.txt"])
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTempFile(t, dir, "sub/note.md", files["sub/note.md"])
	return dir, files
}

func TestISORockRidgeJoliet(t *testing.T) {
	dir, files := isoSrcDir(t)
	img := mkiso(t, "-R", "-J", "-V", "GHEXISO", "-hide-rr-moved", dir)
	f := memFS(t, img)

	if f.Type() != "iso9660" {
		t.Fatalf("type=%s", f.Type())
	}
	if f.Label() != "GHEXISO" {
		t.Fatalf("label=%q", f.Label())
	}
	if f.TotalSize() != int64(len(img)) {
		t.Fatalf("total=%d want %d", f.TotalSize(), len(img))
	}

	root, err := f.List("/")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(root, "hello.txt") {
		t.Fatalf("root: %v", names(root))
	}
	if !contains(root, "sub") {
		t.Fatalf("root missing sub: %v", names(root))
	}
	if findEntry(t, root, "sub").Dir != true {
		t.Fatal("sub should be a dir")
	}

	sub, err := f.List("/sub")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(sub, "note.md") {
		t.Fatalf("sub: %v", names(sub))
	}

	for path, want := range files {
		if got := readAll(t, f, path); !bytes.Equal(got, want) {
			t.Fatalf("%s: got %q want %q", path, got, want)
		}
	}

	// Case-insensitive fallback (ISO 9660 is effectively case-folded).
	if got := readAll(t, f, "/HELLO.TXT"); !bytes.Equal(got, files["hello.txt"]) {
		t.Fatalf("case-insensitive read failed: %q", got)
	}

	// Errors.
	if _, err := f.List("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("list missing: %v", err)
	}
	if _, err := f.List("/hello.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("list file: %v", err)
	}
	if _, err := f.ReadAt("/sub", 0, make([]byte, 1)); !errors.Is(err, ErrIsDir) {
		t.Fatalf("read dir: %v", err)
	}
	if n, err := f.ReadAt("/hello.txt", int64(len(files["hello.txt"])), make([]byte, 4)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("eof: n=%d err=%v", n, err)
	}
}

func TestISOPlainNames(t *testing.T) {
	dir, files := isoSrcDir(t)
	// No Rock Ridge, no Joliet: plain ISO names carry ";1" versions and
	// are typically uppercased.
	img := mkiso(t, "-V", "PLAINLBL", dir)
	f := memFS(t, img)

	if f.Label() != "PLAINLBL" {
		t.Fatalf("label=%q", f.Label())
	}
	root, err := f.List("/")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range root {
		if e.Name != "." && stringsContains(e.Name, ";") {
			t.Fatalf("version suffix leaked: %q", e.Name)
		}
	}
	// genisoimage uppercases 8.3 names without RR.
	if !contains(root, "HELLO.TXT") {
		t.Fatalf("root: %v", names(root))
	}
	if got := readAll(t, f, "/HELLO.TXT"); !bytes.Equal(got, files["hello.txt"]) {
		t.Fatalf("content: %q", got)
	}
}

func TestISORejectsGarbage(t *testing.T) {
	img := make([]byte, 0x8000+2048)
	// No CD001 signature.
	if _, err := Probe(memReader{img}, 0, int64(len(img))); err == nil {
		t.Fatal("expected probe failure for non-ISO image")
	}
}

func stringsContains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}
