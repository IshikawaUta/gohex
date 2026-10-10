//go:build !linux

package fusefs

import (
	"errors"

	internalfs "github.com/IshikawaUta/gohex/internal/fs"
)

// Mount is unavailable outside Linux: macOS and Windows have no FUSE
// equivalent in this codebase, and shelling out to third-party
// drivers would weaken the read-only guarantee.
func Mount(mountpoint string, fsys internalfs.FS, label string) (Handle, error) {
	return nil, errors.New("fusefs: FUSE mounts are only available on Linux")
}
