package service

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/disk"
)

// CloneRequest describes one async clone job.
type CloneRequest struct {
	SrcPath      string `json:"srcPath"`
	DstPattern   string `json:"dstPattern"`
	Compression  string `json:"compression"` // none | gzip | zstd
	SplitSize    int64  `json:"splitSize"`
	Resume       bool   `json:"resume"`
	BadSectorLog string `json:"badSectorLog"`
}

// CloneJobStatus is the live view of one clone job.
type CloneJobStatus struct {
	ID         int64  `json:"id"`
	SrcPath    string `json:"srcPath"`
	DstPattern string `json:"dstPattern"`
	Copied     int64  `json:"copied"`
	Total      int64  `json:"total"`
	BadSectors int64  `json:"badSectors"`
	PartIndex  int    `json:"partIndex"`
	State      string `json:"state"` // running | done | error | cancelled
	Error      string `json:"error,omitempty"`
	Result     string `json:"result,omitempty"` // JSON CloneResult when done
}

// cloneJob tracks one running clone.
type cloneJob struct {
	id     int64
	cancel context.CancelFunc
	status CloneJobStatus
}

// cloneEngine runs one job; it is a var so tests can stub the
// heavy copy out without touching the service surface.
var cloneEngine = disk.Clone

// StartClone begins an asynchronous clone of srcPath. Progress is
// emitted as a "clone:progress" event; the job can be cancelled with
// CancelClone. The source may be a regular file or a block device;
// opening is read-only, and the run is audited as an export.
func (a *App) StartClone(req CloneRequest) (CloneJobStatus, error) {
	if req.SrcPath == "" || req.DstPattern == "" {
		return CloneJobStatus{}, fmt.Errorf("service: clone: source and destination are required")
	}
	srcAbs := absPath(req.SrcPath)
	fi, err := os.Stat(srcAbs)
	if err != nil {
		return CloneJobStatus{}, fmt.Errorf("service: clone: source: %w", err)
	}
	if fi.IsDir() {
		return CloneJobStatus{}, fmt.Errorf("service: clone: source is a directory")
	}
	// Refuse to clone onto the same path as the source.
	dstAbs := absPath(req.DstPattern)
	if filepath.Clean(srcAbs) == filepath.Clean(dstAbs) {
		return CloneJobStatus{}, fmt.Errorf("service: clone: source and destination are the same file")
	}

	f, err := os.Open(srcAbs)
	if err != nil {
		return CloneJobStatus{}, fmt.Errorf("service: clone: open source: %w", err)
	}
	size := fi.Size()
	if size == 0 {
		// Block devices report size 0 via Stat; seek to the end to
		// learn the capacity (works on files and block devices alike).
		if end, serr := f.Seek(0, io.SeekEnd); serr == nil && end > 0 {
			size = end
			_, _ = f.Seek(0, io.SeekStart)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.mu.Lock()
	a.cloneSeq++
	id := a.cloneSeq
	job := &cloneJob{
		id:     id,
		cancel: cancel,
		status: CloneJobStatus{
			ID: id, SrcPath: srcAbs, DstPattern: dstAbs,
			Total: size, State: "running",
		},
	}
	if a.clones == nil {
		a.clones = map[int64]*cloneJob{}
	}
	a.clones[id] = job
	a.mu.Unlock()

	opts := disk.CloneOptions{
		Compression: req.Compression,
		SplitSize:   req.SplitSize,
		Resume:      req.Resume,
	}
	if req.BadSectorLog != "" {
		opts.BadSectorLog = absPath(req.BadSectorLog)
	}
	go func() {
		defer f.Close()
		res, cerr := cloneEngine(ctx, f, size, dstAbs, opts, func(p disk.CloneProgress) {
			a.mu.Lock()
			job.status.Copied = p.Copied
			job.status.BadSectors = p.BadSectors
			job.status.PartIndex = p.PartIndex
			a.mu.Unlock()
			a.event("clone:progress", CloneJobStatus{
				ID: id, SrcPath: srcAbs, DstPattern: dstAbs,
				Copied: p.Copied, Total: size, BadSectors: p.BadSectors,
				PartIndex: p.PartIndex, State: "running",
			})
		})
		a.mu.Lock()
		switch {
		case cerr != nil:
			if ctx.Err() != nil {
				job.status.State = "cancelled"
				job.status.Error = "cancelled"
			} else {
				job.status.State = "error"
				job.status.Error = cerr.Error()
			}
		default:
			job.status.State = "done"
			job.status.Copied = res.BytesCopied
			job.status.BadSectors = res.BadSectors
			job.status.Result = fmt.Sprintf("%+v", res)
		}
		st := job.status
		a.mu.Unlock()
		_ = a.log.Log(audit.Event{
			Action: audit.ActionExport,
			Target: dstAbs,
			Result: audit.ResultOK,
			Detail: map[string]string{
				"op":     "clone",
				"src":    srcAbs,
				"state":  st.State,
				"bytes":  fmt.Sprintf("%d", st.Copied),
				"sha256": res.SourceSHA256,
			},
		})
		a.event("clone:done", st)
	}()
	return job.status, nil
}

// CancelClone requests cancellation of a running job.
func (a *App) CancelClone(id int64) error {
	a.mu.Lock()
	job, ok := a.clones[id]
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("service: clone: no job %d", id)
	}
	job.cancel()
	return nil
}

// CloneStatus returns the live status of one job.
func (a *App) CloneStatus(id int64) (CloneJobStatus, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	job, ok := a.clones[id]
	if !ok {
		return CloneJobStatus{}, fmt.Errorf("service: clone: no job %d", id)
	}
	return job.status, nil
}

// CloneList returns every job this session has started.
func (a *App) CloneList() []CloneJobStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]CloneJobStatus, 0, len(a.clones))
	for _, j := range a.clones {
		out = append(out, j.status)
	}
	return out
}
