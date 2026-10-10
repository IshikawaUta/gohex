package service

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// mkntfsImage builds a small NTFS image seeded with one file via
// ntfscp. Skips when the ntfs-3g tools are not installed.
func mkntfsImage(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("mkntfs"); err != nil {
		t.Skip("mkntfs not installed")
	}
	if _, err := exec.LookPath("ntfscp"); err != nil {
		t.Skip("ntfscp not installed")
	}
	p := filepath.Join(t.TempDir(), "ntfs.img")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(8 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if out, err := exec.Command("mkntfs", "-F", "-L", "ADS", "-s", "512", p).CombinedOutput(); err != nil {
		t.Fatalf("mkntfs: %v %s", err, out)
	}
	src := filepath.Join(t.TempDir(), "hello.txt")
	if err := os.WriteFile(src, []byte("hello ads"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ntfscp", p, src, "/hello.txt").CombinedOutput(); err != nil {
		t.Fatalf("ntfscp: %v %s", err, out)
	}
	return p
}

func TestFsStreamsOnNTFS(t *testing.T) {
	app := newTestApp(t)
	p := mkntfsImage(t)
	// Plain file with no ADS: empty list, no error.
	streams, err := app.FsStreams(p, 0, 0, "/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(streams) != 0 {
		t.Fatalf("streams=%+v", streams)
	}
	// Opening a stream that does not exist must fail cleanly.
	if _, err := app.FsOpenStream(p, 0, 0, "/hello.txt", "secret"); err == nil {
		t.Error("missing stream opened")
	}
	if _, err := app.FsStreamExport(p, 0, 0, "/hello.txt", "secret", filepath.Join(t.TempDir(), "out")); err == nil {
		t.Error("missing stream exported")
	}
	// Empty stream name rejected before any I/O.
	if _, err := app.FsOpenStream(p, 0, 0, "/hello.txt", ""); err == nil {
		t.Error("empty stream name accepted")
	}
	if _, err := app.FsStreamExport(p, 0, 0, "/hello.txt", "", "x"); err == nil {
		t.Error("empty stream export accepted")
	}
}
