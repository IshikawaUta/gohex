package service

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func requireFusermount(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("FUSE mounts are Linux-only")
	}
	if _, err := exec.LookPath("fusermount3"); err != nil {
		if _, err2 := exec.LookPath("fusermount"); err2 != nil {
			t.Skip("fusermount not installed")
		}
	}
}

func TestFsMountRoundTrip(t *testing.T) {
	requireFusermount(t)
	app := newTestApp(t)
	img := mkntfsImage(t)
	mp := filepath.Join(t.TempDir(), "mnt")
	if err := os.Mkdir(mp, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := app.FsMount(img, 0, 0, mp)
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	if info.Mountpoint != mp || info.FSType != "ntfs" {
		t.Fatalf("info=%+v", info)
	}
	// Standard tools can now read the evidence read-only.
	got, err := os.ReadFile(filepath.Join(mp, "hello.txt"))
	if err != nil {
		t.Fatalf("read via mount: %v", err)
	}
	if string(got) != "hello ads" {
		t.Fatalf("content=%q", got)
	}
	// Writes must fail: this is evidence, not a scratch disk.
	werr := os.WriteFile(filepath.Join(mp, "evil.bin"), []byte("x"), 0o644)
	if werr == nil {
		t.Fatal("write through read-only mount succeeded")
	}
	// Double-mount of the same point is refused.
	if _, err := app.FsMount(img, 0, 0, mp); err == nil {
		t.Fatal("double mount accepted")
	}
	// Listing reports the mount.
	mounts := app.FsMountList()
	if len(mounts) != 1 || mounts[0].Mountpoint != mp {
		t.Fatalf("mounts=%+v", mounts)
	}
	if err := app.FsUnmount(mp); err != nil {
		t.Fatalf("unmount: %v", err)
	}
	if _, err := os.ReadFile(filepath.Join(mp, "hello.txt")); err == nil {
		t.Fatal("evidence still visible after unmount")
	}
	// Unmounting twice fails cleanly.
	if err := app.FsUnmount(mp); err == nil {
		t.Fatal("double unmount accepted")
	}
}

func TestFsMountValidation(t *testing.T) {
	requireFusermount(t)
	app := newTestApp(t)
	img := mkntfsImage(t)
	if _, err := app.FsMount(img, 0, 0, ""); err == nil {
		t.Error("empty mountpoint accepted")
	}
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := app.FsMount(img, 0, 0, missing); err == nil {
		t.Error("nonexistent mountpoint accepted")
	}
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o644)
	if _, err := app.FsMount(img, 0, 0, file); err == nil {
		t.Error("file mountpoint accepted")
	}
	nonempty := filepath.Join(t.TempDir(), "busy")
	os.Mkdir(nonempty, 0o755)
	os.WriteFile(filepath.Join(nonempty, "keep.txt"), []byte("live"), 0o644)
	if _, err := app.FsMount(img, 0, 0, nonempty); err == nil {
		t.Error("non-empty mountpoint accepted")
	}
	if err := app.FsUnmount(filepath.Join(t.TempDir(), "ghost")); err == nil {
		t.Error("unmount of unknown point accepted")
	}
	// Invalid image path fails before any mount happens.
	empty := filepath.Join(t.TempDir(), "e")
	os.Mkdir(empty, 0o755)
	if _, err := app.FsMount(filepath.Join(t.TempDir(), "missing.img"), 0, 0, empty); err == nil {
		t.Error("missing image accepted")
	}
}
