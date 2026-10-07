package fs

import "fmt"

// probeApple detects Apple filesystems (HFS, HFS+, APFS) so callers get a
// precise "recognized but not yet implemented" error instead of a generic
// probe failure. Volume parsing lands in a later roadmap stage.
func probeApple(r rangeReader) (FS, error) {
	if r.size >= 2048 {
		vh := make([]byte, 512)
		if err := r.readFull(vh, 1024); err == nil {
			switch string(vh[0:2]) {
			case "H+", "HX":
				return nil, fmt.Errorf("fs: HFS+ detected but not yet supported (roadmap stage 3)")
			case "BD":
				return nil, fmt.Errorf("fs: HFS detected but not yet supported (roadmap stage 3)")
			}
		}
	}
	if r.size >= 4096 {
		nx := make([]byte, 64)
		if err := r.readFull(nx, 0); err == nil && string(nx[32:36]) == "NXSB" {
			return nil, fmt.Errorf("fs: APFS detected but not yet supported (roadmap stage 3)")
		}
	}
	return nil, fmt.Errorf("fs: unrecognized filesystem in range at %#x", r.off)
}
