package service

import (
	"fmt"
	"io"
	"os"

	"github.com/IshikawaUta/gohex/internal/raid"
)

// raidSource adapts a raid.Array to core.Source, owning the member
// file handles so Close releases all of them.
type raidSource struct {
	*raid.Array
	files []*os.File
	name  string
}

func (r *raidSource) Name() string { return r.name }
func (r *raidSource) Close() error {
	var first error
	for _, f := range r.files {
		if err := f.Close(); first == nil {
			first = err
		}
	}
	return first
}

// RaidOpen assembles the listed member files into a read-only logical
// volume and opens it as a hex document. level is "0"/"1"/"5"/"6";
// stripeSize is the stripe unit in bytes (a power of two); missing
// lists member indexes to treat as absent (degraded simulation). The
// members are opened read-only and audited; nothing is ever written.
func (a *App) RaidOpen(paths []string, level string, stripeSize int64, missing []int) (DocInfo, error) {
	if len(paths) == 0 {
		return DocInfo{}, fmt.Errorf("service: raid: no member files")
	}
	lvl, err := raid.ParseLevel(level)
	if err != nil {
		return DocInfo{}, err
	}
	if stripeSize <= 0 {
		stripeSize = 512
	}
	miss := make(map[int]bool, len(missing))
	for _, m := range missing {
		miss[m] = true
	}
	members := make([]raid.Member, len(paths))
	files := make([]*os.File, 0, len(paths))
	cleanup := func() {
		for _, f := range files {
			f.Close()
		}
	}
	for i, p := range paths {
		abs := absPath(p)
		if miss[i] {
			// A missing member still contributes its nominal size so
			// the logical capacity does not collapse; use the largest
			// sibling's size as the stand-in.
			members[i] = raid.Member{Missing: true, Size: 1 << 30}
			continue
		}
		f, oerr := os.Open(abs)
		if oerr != nil {
			cleanup()
			return DocInfo{}, fmt.Errorf("service: raid: member %d: %w", i, oerr)
		}
		files = append(files, f)
		fi, serr := f.Stat()
		if serr != nil {
			cleanup()
			return DocInfo{}, fmt.Errorf("service: raid: member %d: %w", i, serr)
		}
		size := fi.Size()
		if size == 0 {
			if end, eerr := f.Seek(0, io.SeekEnd); eerr == nil && end > 0 {
				size = end
				_, _ = f.Seek(0, io.SeekStart)
			}
		}
		members[i] = raid.Member{ReaderAt: f, Size: size}
	}
	// A fully-missing member with the stand-in size is capped by the
	// smallest REAL member via New's min-size logic only when it has a
	// real ReaderAt; for missing members pass the max sibling size so
	// capacity is not distorted. Recompute: use the smallest real size.
	var realMin int64 = -1
	for i := range members {
		if members[i].Missing {
			continue
		}
		if realMin < 0 || members[i].Size < realMin {
			realMin = members[i].Size
		}
	}
	if realMin < 0 {
		cleanup()
		return DocInfo{}, fmt.Errorf("service: raid: every member is marked missing")
	}
	for i := range members {
		if members[i].Missing {
			members[i].Size = realMin
		}
	}
	arr, aerr := raid.New(members, lvl, stripeSize)
	if aerr != nil {
		cleanup()
		return DocInfo{}, fmt.Errorf("service: raid: %w", aerr)
	}
	name := fmt.Sprintf("raid%d(%s)", lvl, baseName(paths[0]))
	src := &raidSource{Array: arr, files: files, name: name}
	doc, err := a.openContainer(name, src, map[string]string{
		"op":     "raid",
		"level":  lvl.String(),
		"stripe": fmt.Sprintf("%d", stripeSize),
		"disks":  fmt.Sprintf("%d", len(paths)),
	})
	if err != nil {
		src.Close()
		return DocInfo{}, err
	}
	return doc, nil
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
