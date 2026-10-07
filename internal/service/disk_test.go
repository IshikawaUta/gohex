package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	stdhex "encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not installed", name)
	}
}

func runCmd(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

// buildExt2 creates an ext2 image holding files at its root.
func buildExt2(t *testing.T, label string, files map[string]string) []byte {
	t.Helper()
	requireTool(t, "mkfs.ext2")
	requireTool(t, "debugfs")

	img := filepath.Join(t.TempDir(), "fs.img")
	runCmd(t, "mkfs.ext2", "-q", "-F", "-b", "1024", "-L", label, img, "2048")

	srcDir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(srcDir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		runCmd(t, "debugfs", "-w", "-R", "write "+p+" "+name, img)
	}
	data, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// buildMBRDisk places fs at partition start LBA 2048 of a fresh MBR disk.
func buildMBRDisk(t *testing.T, fsData []byte) []byte {
	t.Helper()
	const startLBA = 2048
	if len(fsData)%512 != 0 {
		t.Fatalf("filesystem image length %d is not sector aligned", len(fsData))
	}
	sectors := len(fsData) / 512
	out := make([]byte, (startLBA+sectors)*512)
	e := out[446:]
	e[4] = 0x83 // Linux
	binary.LittleEndian.PutUint32(e[8:], startLBA)
	binary.LittleEndian.PutUint32(e[12:], uint32(sectors))
	out[510], out[511] = 0x55, 0xAA
	binary.LittleEndian.PutUint32(out[440:], 0x474F4845) // disk signature
	copy(out[startLBA*512:], fsData)
	return out
}

func TestProbeImage(t *testing.T) {
	app := newTestApp(t)
	data := bytes.Repeat([]byte("gohex"), 1024)
	p := writeFile(t, "evidence.bin", data)

	info, err := app.ProbeImage(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Format != "raw" || info.Size != int64(len(data)) || info.Path != p {
		t.Fatalf("info = %+v", info)
	}
	if _, err := app.ProbeImage(filepath.Join(t.TempDir(), "missing.img")); err == nil {
		t.Error("ProbeImage(missing): want error")
	}
	if _, err := app.ProbeImage(t.TempDir()); err == nil {
		t.Error("ProbeImage(directory): want error")
	}
}

func TestOpenImageRaw(t *testing.T) {
	app := newTestApp(t)
	data := bytes.Repeat([]byte{0xA5, 0x5A}, 4096)
	p := writeFile(t, "evidence.bin", data)

	info, err := app.OpenImage(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size != int64(len(data)) || info.Name != "evidence.bin" {
		t.Fatalf("info = %+v", info)
	}
	wd, err := app.ReadWindow(info.ID, 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wd.Bytes, data[:16]) {
		t.Fatalf("window = %x", wd.Bytes)
	}
	if _, err := app.OpenImage(filepath.Join(t.TempDir(), "nope.img")); err == nil {
		t.Error("OpenImage(missing): want error")
	}
}

func TestSuperfloppyFilesystem(t *testing.T) {
	app := newTestApp(t)
	payload := "hello from gohex\n"
	fsData := buildExt2(t, "GohexFS", map[string]string{"hello.txt": payload})
	p := writeFile(t, "fs.img", fsData)

	// No partition table: an unpartitioned image still parses.
	layout, err := app.Partitions(p)
	if err != nil {
		t.Fatal(err)
	}
	if layout.Kind != "none" || len(layout.Partitions) != 0 {
		t.Fatalf("layout = %+v", layout)
	}
	if layout.Partitions == nil {
		t.Error("Partitions must serialise as [] not null")
	}

	info, err := app.ProbeFileSystem(p, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != "ext2" || info.Label != "GohexFS" {
		t.Fatalf("fs info = %+v", info)
	}
	if info.Size == 0 || info.Offset != 0 {
		t.Fatalf("fs size/offset = %d/%d", info.Size, info.Offset)
	}

	entries, err := app.FsList(p, 0, 0, "/")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if e.Name == "hello.txt" {
			found = true
			if e.Dir || e.Size != int64(len(payload)) {
				t.Fatalf("entry = %+v", e)
			}
		}
	}
	if !found {
		t.Fatalf("hello.txt not listed in %d entries", len(entries))
	}

	st, err := app.FsStat(p, 0, 0, "/hello.txt")
	if err != nil || st.Dir || st.Size != int64(len(payload)) {
		t.Fatalf("stat = %+v, err = %v", st, err)
	}

	got, err := app.FsRead(p, 0, 0, "/hello.txt", 0, 1024)
	if err != nil || string(got) != payload {
		t.Fatalf("read = %q, err = %v", got, err)
	}
	// Partial read from a middle offset.
	got, err = app.FsRead(p, 0, 0, "/hello.txt", 6, 4)
	if err != nil || string(got) != "from" {
		t.Fatalf("partial read = %q, err = %v", got, err)
	}
}

func TestPartitionedDisk(t *testing.T) {
	app := newTestApp(t)
	payload := "partition payload\n"
	fsData := buildExt2(t, "P1", map[string]string{"data.txt": payload})
	diskData := buildMBRDisk(t, fsData)
	p := writeFile(t, "disk.img", diskData)

	layout, err := app.Partitions(p)
	if err != nil {
		t.Fatal(err)
	}
	if layout.Kind != "mbr" || len(layout.Partitions) != 1 {
		t.Fatalf("layout = %+v", layout)
	}
	part := layout.Partitions[0].Partition
	if part.Start != 2048*512 || part.Size != int64(len(fsData)) {
		t.Fatalf("partition = %+v", part)
	}
	if layout.Partitions[0].Filesystem != "ext2" || layout.Partitions[0].Label != "P1" {
		t.Fatalf("fs probe = %+v", layout.Partitions[0])
	}

	// The partition becomes its own document with its own byte space.
	doc, err := app.OpenRange(p, part.Start, part.Size)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Size != part.Size {
		t.Fatalf("doc size = %d, want %d", doc.Size, part.Size)
	}
	wd, err := app.ReadWindow(doc.ID, 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wd.Bytes, fsData[:16]) {
		t.Fatalf("window = %x, want %x", wd.Bytes, fsData[:16])
	}
	// The same file read through the filesystem view agrees.
	got, err := app.FsRead(p, part.Start, part.Size, "/data.txt", 0, 1<<20)
	if err != nil || string(got) != payload {
		t.Fatalf("read = %q, err = %v", got, err)
	}
}

func TestOpenRangeBounds(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "evidence.bin", patternBytes(4096))

	if _, err := app.OpenRange(p, -1, 0); err == nil {
		t.Error("OpenRange(-1): want error")
	}
	if _, err := app.OpenRange(p, 1<<30, 0); err == nil {
		t.Error("OpenRange(past end): want error")
	}
	// size <= 0 runs to the end of the medium.
	doc, err := app.OpenRange(p, 4000, 0)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Size != 96 {
		t.Fatalf("doc size = %d, want 96", doc.Size)
	}
	// A size past the end is clamped rather than rejected.
	doc, err = app.OpenRange(p, 4000, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Size != 96 {
		t.Fatalf("clamped doc size = %d, want 96", doc.Size)
	}
}

func TestFsExport(t *testing.T) {
	app := newTestApp(t)
	payload := strings.Repeat("chain of custody ", 40000) // ~680 KiB: several export chunks
	fsData := buildExt2(t, "EXP", map[string]string{"evidence.txt": payload})
	p := writeFile(t, "fs.img", fsData)

	dst := filepath.Join(t.TempDir(), "out.txt")
	res, err := app.FsExport(p, 0, 0, "/evidence.txt", dst)
	if err != nil {
		t.Fatal(err)
	}
	if res.BytesSaved != int64(len(payload)) || res.Mode != "export" {
		t.Fatalf("result = %+v", res)
	}
	sum := sha256.Sum256([]byte(payload))
	if res.SHA256 != stdhex.EncodeToString(sum[:]) {
		t.Fatalf("sha256 = %s", res.SHA256)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != payload {
		t.Fatalf("exported %d bytes, err = %v", len(got), err)
	}
}

func TestFsExportErrors(t *testing.T) {
	app := newTestApp(t)
	fsData := buildExt2(t, "EXP", map[string]string{"a.txt": "x"})
	p := writeFile(t, "fs.img", fsData)

	t.Run("destination-exists", func(t *testing.T) {
		dst := writeFile(t, "occupied.txt", []byte("keep"))
		if _, err := app.FsExport(p, 0, 0, "/a.txt", dst); err == nil {
			t.Fatal("want error when the destination already exists")
		}
		got, _ := os.ReadFile(dst)
		if string(got) != "keep" {
			t.Fatalf("existing destination was clobbered: %q", got)
		}
	})
	t.Run("missing-source", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "out.txt")
		if _, err := app.FsExport(p, 0, 0, "/nope.txt", dst); err == nil {
			t.Fatal("want error for a missing source file")
		}
		if _, statErr := os.Stat(dst); statErr == nil {
			t.Fatal("no destination should be left behind")
		}
	})
	t.Run("directory-source", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "out.txt")
		if _, err := app.FsExport(p, 0, 0, "/", dst); err == nil {
			t.Fatal("want error when the source is a directory")
		}
	})
	t.Run("bad-filesystem", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "out.txt")
		if _, err := app.FsExport(t.TempDir()+"/missing.img", 0, 0, "/a.txt", dst); err == nil {
			t.Fatal("want error for a missing image")
		}
	})
}

func TestFsReadErrorsAndClamping(t *testing.T) {
	app := newTestApp(t)
	fsData := buildExt2(t, "CLAMP", map[string]string{"a.txt": "0123456789"})
	p := writeFile(t, "fs.img", fsData)

	if _, err := app.FsRead(p, 0, 0, "/a.txt", -1, 10); err == nil {
		t.Error("FsRead(negative offset): want error")
	}
	if got, err := app.FsRead(p, 0, 0, "/a.txt", 0, 0); err != nil || got != nil {
		t.Errorf("FsRead(zero length) = %v, %v", got, err)
	}
	// A request larger than the read window is clamped, not rejected.
	got, err := app.FsRead(p, 0, 0, "/a.txt", 0, maxReadWindow+1)
	if err != nil || string(got) != "0123456789" {
		t.Fatalf("clamped read = %q, err = %v", got, err)
	}
	if _, err := app.FsRead(p, 0, 0, "/missing", 0, 10); err == nil {
		t.Error("FsRead(missing file): want error")
	}
	if _, err := app.FsStat(p, 0, 0, "/missing"); err == nil {
		t.Error("FsStat(missing file): want error")
	}
	if _, err := app.FsList(p, 0, 0, "/no/such/dir"); err == nil {
		t.Error("FsList(missing dir): want error")
	}
	if _, err := app.ProbeFileSystem(p, -1, 0); err == nil {
		t.Error("ProbeFileSystem(negative offset): want error")
	}
	// A byte range that holds no filesystem is rejected cleanly.
	if _, err := app.ProbeFileSystem(p, 1024, 512); err == nil {
		t.Error("ProbeFileSystem(non-filesystem range): want error")
	}
}

func TestNormalizeFsPath(t *testing.T) {
	for in, want := range map[string]string{
		"":                "/",
		"/":               "/",
		"a":               "/a",
		"/a/b/":           "/a/b",
		"//a//b//":        "//a//b",
		"/a/b/../c/":      "/a/b/../c",
		"/dir with space": "/dir with space",
	} {
		if got := normalizeFsPath(in); got != want {
			t.Errorf("normalizeFsPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSubSource(t *testing.T) {
	base := patternBytes(1024)
	s := &subSource{r: bytes.NewReader(base), name: "x[512:768]", base: 512, size: 256}

	if s.Name() != "x[512:768]" || s.Size() != 256 {
		t.Fatalf("name/size = %q/%d", s.Name(), s.Size())
	}
	buf := make([]byte, 32)
	if n, err := s.ReadAt(buf, 0); n != 32 || err != nil {
		t.Fatalf("ReadAt = (%d, %v)", n, err)
	}
	if !bytes.Equal(buf, base[512:544]) {
		t.Fatal("subSource returned the wrong window")
	}
	// A read crossing the window end is truncated and reports EOF.
	if n, err := s.ReadAt(buf, 240); n != 16 || !errors.Is(err, io.EOF) {
		t.Fatalf("truncated ReadAt = (%d, %v)", n, err)
	}
	if n, err := s.ReadAt(buf, 256); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("at-end ReadAt = (%d, %v)", n, err)
	}
	if n, err := s.ReadAt(buf, -1); n != 0 || err == nil {
		t.Fatalf("negative ReadAt = (%d, %v)", n, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	// A subSource without a closer still closes cleanly.
	s2 := &subSource{r: bytes.NewReader(base), size: 8}
	if err := s2.Close(); err != nil {
		t.Fatalf("Close without closer = %v", err)
	}
}

func TestFsSessionsClosedWithApp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOHEX_AUDIT_LOG", filepath.Join(dir, "audit.jsonl"))
	app, err := New(filepath.Join(dir, "config.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	fsData := buildExt2(t, "CACHE", map[string]string{"a.txt": "x"})
	p := writeFile(t, "fs.img", fsData)

	if _, err := app.ProbeFileSystem(p, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ProbeFileSystem(p, 0, 0); err != nil {
		t.Fatal(err)
	}
	if len(app.fss) != 1 {
		t.Fatalf("cached sessions = %d, want 1", len(app.fss))
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	if len(app.fss) != 0 {
		t.Fatalf("sessions after Close = %d, want 0", len(app.fss))
	}
}

func patternBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i * 37) ^ (i >> 2))
	}
	return b
}
