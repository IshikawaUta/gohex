// Package fusefs mounts an internal/fs filesystem as a read-only FUSE
// volume so evidence can be browsed with ordinary tools (ls, cp, md5sum)
// without ever granting write access. Linux only; other platforms get a
// stub that returns an error.
package fusefs

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	internalfs "github.com/IshikawaUta/gohex/internal/fs"
)

// registry assigns stable inode numbers per mount.
type registry struct {
	mu     sync.Mutex
	next   uint64
	inodes map[string]uint64 // fs path → inode
}

func (r *registry) ino(p string) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n, ok := r.inodes[p]; ok {
		return n
	}
	r.next++
	r.inodes[p] = r.next
	return r.next
}

// dirNode is a read-only directory backed by an internal/fs FS.
type dirNode struct {
	fs.Inode
	fsys internalfs.FS
	p    string
	reg  *registry
}

// fileNode is a read-only file backed by an internal/fs FS.
type fileNode struct {
	fs.Inode
	fsys  internalfs.FS
	p     string
	reg   *registry
	entry internalfs.Entry
}

// handle serves file reads; it carries no write state.
type handle struct {
	fsys internalfs.FS
	p    string
}

var (
	_ fs.NodeLookuper  = (*dirNode)(nil)
	_ fs.NodeReaddirer = (*dirNode)(nil)
	_ fs.NodeGetattrer = (*dirNode)(nil)
	_ fs.NodeLookuper  = (*fileNode)(nil)
	_ fs.NodeGetattrer = (*fileNode)(nil)
	_ fs.NodeOpener    = (*fileNode)(nil)
	_ fs.FileReader    = (*handle)(nil)
)

func childPath(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

func (d *dirNode) Lookup(_ context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	cp := childPath(d.p, name)
	st, err := d.fsys.Stat(cp)
	if err != nil {
		if errors.Is(err, internalfs.ErrNotFound) {
			return nil, syscall.ENOENT
		}
		return nil, syscall.EIO
	}
	ino := d.reg.ino(cp)
	mode := uint32(syscall.S_IFREG | 0o444)
	if st.Dir {
		mode = syscall.S_IFDIR | 0o555
	}
	child := d.NewInode(context.Background(), d.build(st, cp), fs.StableAttr{Mode: mode, Ino: ino})
	fillEntryOut(out, st, mode)
	return child, 0
}

func (d *dirNode) build(st internalfs.Entry, cp string) fs.InodeEmbedder {
	if st.Dir {
		return &dirNode{fsys: d.fsys, p: cp, reg: d.reg}
	}
	return &fileNode{fsys: d.fsys, p: cp, reg: d.reg, entry: st}
}

func (d *dirNode) Readdir(_ context.Context) (fs.DirStream, syscall.Errno) {
	entries, err := d.fsys.List(d.p)
	if err != nil {
		return nil, syscall.EIO
	}
	list := make([]fuse.DirEntry, 0, len(entries))
	for _, e := range entries {
		if e.Deleted {
			// Unlinked names are best-effort; they cannot be opened
			// reliably and would confuse standard tools.
			continue
		}
		mode := uint32(syscall.S_IFREG)
		if e.Dir {
			mode = syscall.S_IFDIR
		}
		list = append(list, fuse.DirEntry{
			Name: e.Name,
			Mode: mode,
			Ino:  d.reg.ino(childPath(d.p, e.Name)),
		})
	}
	return fs.NewListDirStream(list), 0
}

func (d *dirNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = syscall.S_IFDIR | 0o555
	out.Nlink = 2
	return 0
}

func (n *fileNode) Lookup(_ context.Context, _ string, _ *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	return nil, syscall.ENOENT
}

func (n *fileNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	fillAttr(&out.Attr, n.entry, n.reg.ino(n.p))
	return 0
}

func (n *fileNode) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if flags&(syscall.O_RDWR|syscall.O_WRONLY) != 0 {
		return nil, 0, syscall.EROFS
	}
	return &handle{fsys: n.fsys, p: n.p}, fuse.FOPEN_DIRECT_IO, 0
}

func (h *handle) Read(_ context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	n, err := h.fsys.ReadAt(h.p, off, dest)
	if n > 0 && (err == nil || errors.Is(err, io.EOF)) {
		return fuse.ReadResultData(dest[:n]), 0
	}
	if errors.Is(err, io.EOF) || n == 0 {
		return fuse.ReadResultData(nil), 0
	}
	return nil, syscall.EIO
}

func fillEntryOut(out *fuse.EntryOut, st internalfs.Entry, mode uint32) {
	fillAttr(&out.Attr, st, 0)
	out.Mode = mode
	out.Nlink = 1
	if st.Dir {
		out.Nlink = 2
	}
}

func fillAttr(a *fuse.Attr, st internalfs.Entry, ino uint64) {
	a.Size = uint64(st.Size)
	a.Mode = syscall.S_IFREG | 0o444
	a.Nlink = 1
	if st.Dir {
		a.Mode = syscall.S_IFDIR | 0o555
		a.Size = 0
		a.Nlink = 2
	}
	if !st.Modified.IsZero() {
		a.Mtime = uint64(st.Modified.Unix())
		a.Mtimensec = uint32(st.Modified.Nanosecond())
	}
	if !st.Created.IsZero() {
		a.Ctime = uint64(st.Created.Unix())
		a.Ctimensec = uint32(st.Created.Nanosecond())
	}
	if ino != 0 {
		a.Ino = ino
	}
}

// mountHandle is a live mount: it owns the FUSE server and answers Unmount.
type mountHandle struct {
	server *fuse.Server
	info   MountInfo
}

func (h *mountHandle) Unmount() error  { return h.server.Unmount() }
func (h *mountHandle) Info() MountInfo { return h.info }

// Mount mounts fsys read-only at mountpoint and returns a live
// handle. The caller owns it (Unmount when done). Nothing in the
// mounted tree is ever writable: every node advertises mode 0444/0555,
// Open refuses write flags, and the kernel-level "ro" option rejects
// writes before they reach us.
func Mount(mountpoint string, fsys internalfs.FS, label string) (Handle, error) {
	if mountpoint == "" {
		return nil, errors.New("fusefs: empty mountpoint")
	}
	reg := &registry{inodes: map[string]uint64{}}
	root := &dirNode{fsys: fsys, p: "/", reg: reg}
	fsn := "gohex"
	ft := fsys.Type()
	if label != "" {
		fsn = "gohex:" + strings.ReplaceAll(label, " ", "_")
	}
	server, err := fs.Mount(mountpoint, root, &fs.Options{
		MountOptions: fuse.MountOptions{
			// "ro" makes the kernel itself reject writes before they
			// even reach us; node modes (0444/0555) and Open's write
			// rejection are defense in depth.
			Options:  []string{"ro"},
			FsName:   fsn,
			Name:     "gohex",
			MaxWrite: 1 << 20,
		},
		// Pin negative/positive dentries briefly so a slow image read
		// does not stall every stat, but pick up evidence changes
		// (e.g. a re-opened image) within a second.
		EntryTimeout: &[]time.Duration{time.Second}[0],
		AttrTimeout:  &[]time.Duration{time.Second}[0],
	})
	if err != nil {
		return nil, err
	}
	return &mountHandle{
		server: server,
		info:   MountInfo{Mountpoint: mountpoint, FSType: ft, Label: label},
	}, nil
}
