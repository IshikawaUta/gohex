//go:build linux

package fusefs

import (
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"

	internalfs "github.com/IshikawaUta/gohex/internal/fs"
)

func TestRegistryStableInodes(t *testing.T) {
	r := &registry{inodes: map[string]uint64{}}
	a := r.ino("/a")
	b := r.ino("/b")
	if a == b {
		t.Fatalf("distinct paths share inode %d", a)
	}
	if again := r.ino("/a"); again != a {
		t.Fatalf("inode not stable: %d != %d", again, a)
	}
}

func TestChildPath(t *testing.T) {
	if got := childPath("/", "x"); got != "/x" {
		t.Errorf("root child: %q", got)
	}
	if got := childPath("/a/b", "c"); got != "/a/b/c" {
		t.Errorf("nested child: %q", got)
	}
}

func TestFillAttrFile(t *testing.T) {
	mtime := time.Date(2024, 5, 6, 7, 8, 9, 123456789, time.UTC)
	st := internalfs.Entry{Size: 4096, Modified: mtime, Created: mtime}
	var a fuse.Attr
	fillAttr(&a, st, 42)
	if a.Size != 4096 || a.Ino != 42 {
		t.Fatalf("attr=%+v", a)
	}
	if a.Mode&syscall.S_IFMT != syscall.S_IFREG || a.Mode&0o222 != 0 {
		t.Errorf("file mode=%o must be regular and not writable", a.Mode)
	}
	if a.Mtime != uint64(mtime.Unix()) || a.Mtimensec != uint32(mtime.Nanosecond()) {
		t.Errorf("mtime not carried: %d.%d", a.Mtime, a.Mtimensec)
	}
}

func TestFillAttrDir(t *testing.T) {
	var a fuse.Attr
	fillAttr(&a, internalfs.Entry{Dir: true}, 1)
	if a.Mode&syscall.S_IFMT != syscall.S_IFDIR || a.Mode&0o222 != 0 {
		t.Errorf("dir mode=%o", a.Mode)
	}
	if a.Nlink != 2 {
		t.Errorf("dir nlink=%d", a.Nlink)
	}
}
