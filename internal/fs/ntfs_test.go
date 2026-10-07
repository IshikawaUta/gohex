package fs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// mkntfs builds an NTFS image and seeds it with files via ntfscp.
// Files land in the root directory (no mkdir tool ships with ntfs-3g);
// seeding ~20 entries forces the root index into INDEX_ALLOCATION.
func mkntfs(t *testing.T, sizeMB int, seed map[string][]byte) []byte {
	t.Helper()
	requireTool(t, "mkntfs")
	requireTool(t, "ntfscp")
	p := filepath.Join(t.TempDir(), "ntfs.img")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(sizeMB) << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	runCmd(t, "mkntfs", "-F", "-L", "GHEXNTFS", "-s", "512", p)

	src := t.TempDir()
	// Deterministic order for reproducible images.
	keys := make([]string, 0, len(seed))
	for k := range seed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, name := range keys {
		writeTempFile(t, src, strings.ReplaceAll(name, "/", "_"), seed[name])
		runCmd(t, "ntfscp", p, filepath.Join(src, strings.ReplaceAll(name, "/", "_")), "/"+name)
	}
	img, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func TestNTFSProbeAndRead(t *testing.T) {
	seed := map[string][]byte{
		"hello.txt":                  []byte("Hello NTFS!\n"),
		"big.bin":                    bytes.Repeat([]byte("ntfs-runlist-0123456789"), 3000), // ~69 KB, non-resident
		"quarterly report 2024.xlsx": []byte("spreadsheet bytes"),
	}
	for i := 0; i < 20; i++ {
		name := "pad" + string(rune('a'+i%26)) + string(rune('0'+i/26)) + ".txt"
		seed[name] = []byte("padding file with some content to land beyond the index root\n")
	}
	img := mkntfs(t, 64, seed)
	f := memFS(t, img)

	if f.Type() != "ntfs" {
		t.Fatalf("type=%s", f.Type())
	}
	if f.Label() != "GHEXNTFS" {
		t.Fatalf("label=%q", f.Label())
	}
	if f.TotalSize() != int64(len(img)) {
		t.Fatalf("total=%d want %d", f.TotalSize(), len(img))
	}

	root, err := f.List("/")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"hello.txt", "big.bin", "quarterly report 2024.xlsx"} {
		if !contains(root, n) {
			t.Fatalf("root missing %q: %v", n, names(root))
		}
	}

	for path, want := range seed {
		if got := readAll(t, f, "/"+path); !bytes.Equal(got, want) {
			t.Fatalf("%s: got %d bytes want %d", path, len(got), len(want))
		}
	}

	// Case-insensitive resolution.
	if got := readAll(t, f, "/HELLO.TXT"); !bytes.Equal(got, seed["hello.txt"]) {
		t.Fatal("case-insensitive read failed")
	}

	// Stat metadata.
	st, err := f.Stat("/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if st.Size != int64(len(seed["hello.txt"])) {
		t.Fatalf("size=%d", st.Size)
	}
	if st.Modified.IsZero() {
		t.Fatal("mtime should be set")
	}
	if findEntry(t, root, "hello.txt").Dir {
		t.Fatal("hello.txt should be a file")
	}

	// Errors.
	if _, err := f.List("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("list missing: %v", err)
	}
	if _, err := f.List("/hello.txt"); !errors.Is(err, ErrNotDir) {
		t.Fatalf("list file: %v", err)
	}
	if _, err := f.ReadAt("/missing", 0, make([]byte, 1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read missing: %v", err)
	}
	if n, err := f.ReadAt("/hello.txt", int64(len(seed["hello.txt"])), make([]byte, 4)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("eof: n=%d err=%v", n, err)
	}
}

// TestNTFSCrossCheck validates the reader listing against ntfsls, the
// reference tool from ntfs-3g.
func TestNTFSCrossCheck(t *testing.T) {
	requireTool(t, "ntfsls")
	seed := map[string][]byte{
		"alpha.txt":               []byte("aaa"),
		"beta.txt":                []byte("bbb"),
		"gamma.log":               []byte("ccc"),
		"Document Number One.pdf": []byte("%PDF-1.4 fake"),
	}
	for i := 0; i < 24; i++ {
		seed["f"+itoa(i)+".dat"] = []byte(strings.Repeat("x", 100+i))
	}
	imgPath := filepath.Join(t.TempDir(), "ntfs.img")
	f, _ := os.Create(imgPath)
	f.Truncate(64 << 20)
	f.Close()
	runCmd(t, "mkntfs", "-F", "-L", "X", "-s", "512", imgPath)
	src := t.TempDir()
	keys := make([]string, 0, len(seed))
	for k := range seed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, name := range keys {
		writeTempFile(t, src, name, seed[name])
		runCmd(t, "ntfscp", imgPath, filepath.Join(src, name), "/"+name)
	}
	img, err := os.ReadFile(imgPath)
	if err != nil {
		t.Fatal(err)
	}
	fsys := memFS(t, img)

	// Reference listing: "name" per line (skip header lines).
	out := runCmdOut(t, "ntfsls", imgPath)
	want := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Volume") ||
			strings.HasPrefix(line, "WARNING") || strings.HasPrefix(line, "Dumping") ||
			line == "Directory listing for root folder:" {
			continue
		}
		if !strings.Contains(line, ":") && !strings.Contains(line, "/") {
			want[line] = true
		}
	}
	if len(want) == 0 {
		t.Skipf("unexpected ntfsls output:\n%s", out)
	}
	got, err := fsys.List("/")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range got {
		if e.Name == "$Volume" || strings.HasPrefix(e.Name, "$") {
			continue // system files hidden by default in ntfsls
		}
		if !want[e.Name] {
			t.Errorf("reader has %q which ntfsls does not list; ntfsls output:\n%s", e.Name, out)
		}
		delete(want, e.Name)
	}
	for name := range want {
		t.Errorf("ntfsls lists %q which the reader missed", name)
	}
}

func TestNTFSRejectsGarbage(t *testing.T) {
	img := make([]byte, 16*1024)
	img[510], img[511] = 0x55, 0xAA
	if _, err := Probe(memReader{img}, 0, int64(len(img))); err == nil {
		t.Fatal("expected probe failure")
	}
}
