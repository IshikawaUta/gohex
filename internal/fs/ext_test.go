package fs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// mkext builds an ext image and returns it as bytes.
func mkext(t *testing.T, mkfs string, sizeMB int, label string, extra ...string) []byte {
	t.Helper()
	requireTool(t, mkfs)
	p := filepath.Join(t.TempDir(), "ext.img")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(sizeMB) << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	args := []string{"-q", "-F", "-L", label}
	args = append(args, extra...)
	args = append(args, p)
	runCmd(t, mkfs, args...)
	img, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// dbg runs one debugfs command against the image file at path.
func dbg(t *testing.T, path, cmd string) {
	t.Helper()
	requireTool(t, "debugfs")
	runCmd(t, "debugfs", "-w", "-R", cmd, path)
}

// mkextWithFiles creates an ext4 image with a small directory tree,
// populated through debugfs (no mount required).
func mkextWithFiles(t *testing.T, mkfs string, sizeMB int, label string, extra ...string) (img []byte, files map[string][]byte) {
	t.Helper()
	requireTool(t, mkfs)
	requireTool(t, "debugfs")
	p := filepath.Join(t.TempDir(), "ext.img")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(sizeMB) << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	args := []string{"-q", "-F", "-L", label}
	args = append(args, extra...)
	args = append(args, p)
	runCmd(t, mkfs, args...)

	hello := []byte("Hello ext world!\n")
	big := bytes.Repeat([]byte("ext-indirect-0123456789"), 4300) // ~99 KiB
	nested := []byte("deep thoughts\n")
	src := t.TempDir()
	writeTempFile(t, src, "hello.txt", hello)
	writeTempFile(t, src, "big.bin", big)

	dbg(t, p, "write "+filepath.Join(src, "hello.txt")+" /hello.txt")
	dbg(t, p, "write "+filepath.Join(src, "big.bin")+" /big.bin")
	dbg(t, p, "mkdir /docs")
	writeTempFile(t, src, "notes.txt", nested)
	dbg(t, p, "write "+filepath.Join(src, "notes.txt")+" /docs/notes.txt")

	// Independent cross-check that the tree exists the way we expect.
	out := runCmdOut(t, "debugfs", "-R", "ls -p /", p)
	if !bytes.Contains(out, []byte("hello.txt")) {
		t.Fatalf("debugfs does not see hello.txt:\n%s", out)
	}

	img, err = os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return img, map[string][]byte{
		"/hello.txt":      hello,
		"/big.bin":        big,
		"/docs/notes.txt": nested,
	}
}

func runCmdOut(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return out
}

func TestExt4ProbeAndRead(t *testing.T) {
	img, files := mkextWithFiles(t, "mkfs.ext4", 64, "GHEXTST", "-O", "^huge_file")
	f := memFS(t, img)

	if f.Type() != "ext4" {
		t.Fatalf("type=%s", f.Type())
	}
	if f.Label() != "GHEXTST" {
		t.Fatalf("label=%q", f.Label())
	}
	if f.TotalSize() != int64(len(img)) {
		t.Fatalf("total=%d want %d", f.TotalSize(), len(img))
	}

	root, err := f.List("/")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"hello.txt", "big.bin", "docs"} {
		if !contains(root, n) {
			t.Fatalf("root missing %q: %v", n, names(root))
		}
	}
	if findEntry(t, root, "docs").Dir != true {
		t.Fatal("docs should be a directory")
	}

	for path, want := range files {
		if got := readAll(t, f, path); !bytes.Equal(got, want) {
			t.Fatalf("%s: got %d bytes, want %d", path, len(got), len(want))
		}
	}
	// big.bin spans indirect blocks; spot-check the tail.
	if got := readAll(t, f, "/big.bin"); got[len(got)-1] != '9' {
		t.Fatalf("big tail=%q", got[len(got)-4:])
	}

	docs, err := f.List("/docs")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(docs, "notes.txt") {
		t.Fatalf("docs listing: %v", names(docs))
	}

	// ext is case-sensitive by design.
	if _, err := f.Stat("/HELLO.TXT"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("case sensitivity: %v", err)
	}
	// Error paths.
	if _, err := f.List("/hello.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("list file: %v", err)
	}
	if _, err := f.ReadAt("/docs", 0, make([]byte, 1)); !errors.Is(err, ErrIsDir) {
		t.Fatalf("read dir: %v", err)
	}
	if _, err := f.List("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("list missing: %v", err)
	}
	// EOF behaviour past the end.
	if n, err := f.ReadAt("/hello.txt", int64(len(files["/hello.txt"])), make([]byte, 4)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("eof: n=%d err=%v", n, err)
	}
}

func TestExt2Probe(t *testing.T) {
	img := mkext(t, "mkfs.ext2", 32, "EXT2LBL")
	f := memFS(t, img)
	if f.Type() != "ext2" {
		t.Fatalf("type=%s", f.Type())
	}
	if f.Label() != "EXT2LBL" {
		t.Fatalf("label=%q", f.Label())
	}
	root, err := f.List("/")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(root, "lost+found") {
		t.Fatalf("root: %v", names(root))
	}
	if findEntry(t, root, "lost+found").Dir != true {
		t.Fatal("lost+found should be a dir")
	}
}

func TestExt3Detection(t *testing.T) {
	// ext4 without the extent feature is what we classify as ext3.
	img := mkext(t, "mkfs.ext4", 32, "EXT3LBL", "-O", "^extent,^64bit")
	f := memFS(t, img)
	if f.Type() != "ext3" {
		t.Fatalf("type=%s", f.Type())
	}
}
