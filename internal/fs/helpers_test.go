package fs

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// memReader adapts a byte slice to the Reader interface for tests.
type memReader struct{ b []byte }

func (m memReader) Size() int64 { return int64(len(m.b)) }
func (m memReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m.b)) {
		return 0, io.EOF
	}
	n := copy(p, m.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// requireTool skips the test when an external image factory is missing.
func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not installed", name)
	}
}

// runCmd runs a command and fails the test on error.
func runCmd(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

// memFS opens a byte image through Probe for tests.
func memFS(t *testing.T, img []byte) FS {
	t.Helper()
	f, err := Probe(memReader{img}, 0, int64(len(img)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return f
}

// readAll reads a whole file through FS.ReadAt.
func readAll(t *testing.T, f FS, path string) []byte {
	t.Helper()
	st, err := f.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q): %v", path, err)
	}
	if st.Dir {
		t.Fatalf("Stat(%q) is a dir", path)
	}
	buf := make([]byte, st.Size)
	off := 0
	for off < len(buf) {
		n, err := f.ReadAt(path, int64(off), buf[off:])
		off += n
		if err != nil && !(err.Error() == "EOF" && off == len(buf)) {
			if n == 0 {
				t.Fatalf("ReadAt(%q) at %d: %v", path, off, err)
			}
		}
		if n == 0 {
			t.Fatalf("ReadAt(%q) stuck at %d: %v", path, off, err)
		}
	}
	return buf
}

// findEntry returns the entry with the given name from a listing.
func findEntry(t *testing.T, ents []Entry, name string) Entry {
	t.Helper()
	for _, e := range ents {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("entry %q not found in %d entries", name, len(ents))
	return Entry{}
}

// writeTempFile writes data to a temp file and returns its path.
func writeTempFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func contains(ents []Entry, name string) bool {
	for _, e := range ents {
		if e.Name == name {
			return true
		}
	}
	return false
}

func names(ents []Entry) []string {
	out := make([]string, len(ents))
	for i, e := range ents {
		out[i] = e.Name
	}
	return out
}
