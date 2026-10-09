package fs

import "fmt"

// probeApple detects and opens Apple filesystems (HFS+, HFSX, APFS). Old
// HFS ("BD" wrapper) is recognized but intentionally unsupported: it has no
// B-tree/CNID model compatible with the HFS+ reader and is rare on modern
// evidence images.
func probeApple(r rangeReader) (FS, error) {
	if r.size >= 2048 {
		vh := make([]byte, 512)
		if err := r.readFull(vh, 1024); err == nil {
			switch string(vh[0:2]) {
			case "H+", "HX":
				return newHFSPlus(r, vh)
			case "BD":
				return nil, fmt.Errorf("fs: HFS detected but not yet supported")
			}
		}
	}
	if r.size >= 4096 {
		nx := make([]byte, 64)
		if err := r.readFull(nx, 0); err == nil && string(nx[32:36]) == "NXSB" {
			return newAPFS(r)
		}
	}
	return nil, fmt.Errorf("fs: unrecognized filesystem in range at %#x", r.off)
}
