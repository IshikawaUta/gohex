package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/fusefs"
)

// MountInfo describes one active read-only FUSE mount.
type MountInfo struct {
	Mountpoint string `json:"mountpoint"`
	FSType     string `json:"fsType"`
	Label      string `json:"label"`
	Source     string `json:"source"`
}

// FsMount presents the filesystem at offset inside the image as a
// read-only FUSE mount at mountpoint (Linux only). The mountpoint must
// be an existing empty directory: mounting over a non-empty directory
// would hide live files behind evidence, which is exactly the kind of
// confusion this tool exists to prevent. Nothing under the mount is
// writable — the kernel gets the "ro" option, every node advertises
// 0444/0555, and the opener rejects write flags.
func (a *App) FsMount(path string, offset, size int64, mountpoint string) (MountInfo, error) {
	if mountpoint == "" {
		return MountInfo{}, errors.New("service: fuse: empty mountpoint")
	}
	abs := absPath(path)
	mp := filepath.Clean(mountpoint)
	fi, err := os.Stat(mp)
	if err != nil {
		return MountInfo{}, fmt.Errorf("service: fuse: mountpoint: %w", err)
	}
	if !fi.IsDir() {
		return MountInfo{}, errors.New("service: fuse: mountpoint is not a directory")
	}
	if entries, rerr := os.ReadDir(mp); rerr == nil && len(entries) > 0 {
		return MountInfo{}, errors.New("service: fuse: mountpoint is not empty")
	}
	a.mu.Lock()
	if _, exists := a.mounts[mp]; exists {
		a.mu.Unlock()
		return MountInfo{}, errors.New("service: fuse: mountpoint already mounted")
	}
	a.mu.Unlock()

	f, err := a.fsOpen(abs, offset, size)
	if err != nil {
		return MountInfo{}, err
	}
	label := f.Label()
	h, merr := fusefs.Mount(mp, f, label)
	if merr != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionMount,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"mountpoint": mp, "error": merr.Error()},
		})
		return MountInfo{}, fmt.Errorf("service: fuse: %w", merr)
	}
	a.mu.Lock()
	a.mounts[mp] = mountEntry{h: h, src: abs}
	a.mu.Unlock()
	info := MountInfo{
		Mountpoint: mp,
		FSType:     f.Type(),
		Label:      label,
		Source:     abs,
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionMount,
		Target: abs,
		Result: audit.ResultOK,
		Detail: map[string]string{
			"mountpoint": mp,
			"fsType":     info.FSType,
			"label":      label,
			"mode":       "read-only",
		},
	})
	a.event("mounts:changed", nil)
	return info, nil
}

// FsUnmount detaches a FUSE mount. The kernel may need a moment after
// the last open handle closes, so a single retry covers busy mounts
// from tools like md5sum that are mid-read.
func (a *App) FsUnmount(mountpoint string) error {
	mp := filepath.Clean(mountpoint)
	a.mu.Lock()
	me, ok := a.mounts[mp]
	if ok {
		delete(a.mounts, mp)
	}
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("service: fuse: no such mount %q", mountpoint)
	}
	h := me.h
	var err error
	for i := 0; i < 3; i++ {
		err = h.Unmount()
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	result := audit.ResultOK
	detail := map[string]string{"mountpoint": mp}
	if err != nil {
		result = audit.ResultError
		detail["error"] = err.Error()
		// Put it back so a retry is possible once the busy reader exits.
		a.mu.Lock()
		a.mounts[mp] = me
		a.mu.Unlock()
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionUnmount,
		Target: h.Info().Source,
		Result: result,
		Detail: detail,
	})
	a.event("mounts:changed", nil)
	if err != nil {
		return fmt.Errorf("service: fuse: unmount: %w", err)
	}
	return nil
}

// FsMountList returns the active FUSE mounts.
func (a *App) FsMountList() []MountInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]MountInfo, 0, len(a.mounts))
	for mp, me := range a.mounts {
		i := me.h.Info()
		out = append(out, MountInfo{
			Mountpoint: mp,
			FSType:     i.FSType,
			Label:      i.Label,
			Source:     me.src,
		})
	}
	return out
}

// ShutdownUnmounts detaches every FUSE mount during app shutdown so
// the kernel is not left with a dead daemon mount.
func (a *App) ShutdownUnmounts() {
	a.mu.Lock()
	hs := make(map[string]mountEntry, len(a.mounts))
	for k, v := range a.mounts {
		hs[k] = v
	}
	a.mounts = make(map[string]mountEntry)
	a.mu.Unlock()
	for _, me := range hs {
		for i := 0; i < 3; i++ {
			if me.h.Unmount() == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}
