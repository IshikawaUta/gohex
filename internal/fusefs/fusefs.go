// Package fusefs mounts an internal/fs filesystem as a read-only FUSE
// volume so evidence can be browsed with ordinary tools (ls, cp, md5sum)
// without ever granting write access. Linux only; other platforms get a
// stub that returns an error.
package fusefs

// MountInfo describes an active mount.
type MountInfo struct {
	Mountpoint string `json:"mountpoint"`
	FSType     string `json:"fsType"`
	Label      string `json:"label"`
	Source     string `json:"source"`
}

// Handle is a live mount. The caller must call Unmount when finished;
// dropping the handle without unmounting leaves the mount in place
// until the process exits.
type Handle interface {
	// Unmount detaches the mount. It is safe to call more than once.
	Unmount() error
	// Info returns the mount's static description.
	Info() MountInfo
}
