// Package disk gains disk-clone v2 here: a forensically-sound
// sector-stream copier with optional gzip/zstd compression, output
// splitting, resume-from-state, bad-sector logging and SHA-256
// verification of both source and destination. The engine is pure Go
// and only depends on io.ReaderAt + a size, so it works on files,
// block devices, and any future Source implementation alike.
package disk

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

// Compression names accepted by CloneOptions.Compression.
const (
	CompressNone = "none"
	CompressGzip = "gzip"
	CompressZstd = "zstd"
)

// CloneOptions configures one clone run.
type CloneOptions struct {
	// Compression selects none / gzip / zstd for the destination
	// stream. Splitting and resume are only meaningful with
	// Compression=none because compressed streams are not seekable.
	Compression string `json:"compression"`
	// SplitSize, when > 0 and Compression=none, rolls the output to a
	// new file named dstPattern (containing %d) every SplitSize bytes.
	SplitSize int64 `json:"splitSize"`
	// Resume reads a state file written by a previous interrupted run
	// and continues from its offset.
	Resume bool `json:"resume"`
	// BadSectorLog, when non-empty, is a path to append one line per
	// unreadable sector range to ("start\tlength\terror").
	BadSectorLog string `json:"badSectorLog"`
}

// CloneProgress is reported after every copied chunk.
type CloneProgress struct {
	Copied     int64 `json:"copied"`
	Total      int64 `json:"total"`
	BadSectors int64 `json:"badSectors"`
	PartIndex  int   `json:"partIndex"`
}

// CloneResult summarises a finished clone.
type CloneResult struct {
	DestPath     string   `json:"destPath"`
	Parts        []string `json:"parts"`
	BytesCopied  int64    `json:"bytesCopied"`
	BadSectors   int64    `json:"badSectors"`
	SourceSHA256 string   `json:"sourceSha256"`
	DestSHA256   string   `json:"destSha256"`
}

// cloneState is the on-disk resume record, written atomically after
// every rolled part so an interrupted clone can pick up exactly where
// it stopped.
type cloneState struct {
	Copied int64    `json:"copied"`
	Parts  []string `json:"parts"`
}

// statePathFor derives the resume-state path from the destination
// pattern (%d is replaced with "state" so the glob is unambiguous).
func statePathFor(dstPattern string) string {
	if strings.Contains(dstPattern, "%d") {
		return strings.Replace(dstPattern, "%d", "state", 1) + ".clone-state.json"
	}
	return dstPattern + ".clone-state.json"
}

// Clone streams [0, srcSize) from src to dstPattern. A read error that
// is not EOF counts as a bad sector: the copier logs the range, writes
// zeros in its place (the standard forensic practice of "read error →
// fill, log, continue"), and keeps going. Cancelling ctx stops the run
// and leaves the state file behind so Resume can pick it up later.
// For compression=none the destination is re-hashed and compared with
// the source hash; a mismatch is an error, never a silent success.
func Clone(ctx context.Context, src io.ReaderAt, srcSize int64, dstPattern string, opts CloneOptions, progress func(CloneProgress)) (CloneResult, error) {
	if srcSize < 0 {
		return CloneResult{}, errors.New("disk: clone: negative source size")
	}
	switch opts.Compression {
	case "", CompressNone:
		opts.Compression = CompressNone
	case CompressGzip, CompressZstd:
		if opts.SplitSize > 0 {
			return CloneResult{}, errors.New("disk: clone: split requires compression=none")
		}
		if opts.Resume {
			return CloneResult{}, errors.New("disk: clone: resume requires compression=none")
		}
	default:
		return CloneResult{}, fmt.Errorf("disk: clone: unknown compression %q", opts.Compression)
	}
	if opts.SplitSize > 0 && !strings.Contains(dstPattern, "%d") {
		return CloneResult{}, errors.New("disk: clone: split pattern must contain %d")
	}

	statePath := statePathFor(dstPattern)
	var start int64
	var priorParts []string
	if opts.Resume {
		if b, err := os.ReadFile(statePath); err == nil {
			var st cloneState
			if json.Unmarshal(b, &st) == nil && st.Copied >= 0 && st.Copied <= srcSize {
				start = st.Copied
				priorParts = st.Parts
			}
		}
	}

	dst := &cloneDest{}
	if err := dst.open(dstPattern, opts, start, priorParts); err != nil {
		return CloneResult{}, err
	}
	h := sha256.New()
	// On resume the hash must cover the already-copied prefix too:
	// re-hash the prior part files (which contain exactly [0, start))
	// so the final digest is of the whole source, not just this run.
	if start > 0 {
		ph := make([]byte, 1<<20)
		for _, p := range priorParts {
			if err := hashOne(h, p, ph); err != nil {
				dst.abort()
				return CloneResult{}, fmt.Errorf("disk: clone: resume hash: %w", err)
			}
		}
	}
	bw := bufio.NewWriterSize(dst, 1<<20)
	buf := make([]byte, 1<<20)
	const chunk = int64(1 << 20)
	copied := start
	var bad int64
	var badLog *os.File
	if opts.BadSectorLog != "" {
		f, err := os.OpenFile(opts.BadSectorLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			dst.abort()
			return CloneResult{}, fmt.Errorf("disk: clone: bad-sector log: %w", err)
		}
		badLog = f
		defer badLog.Close()
	}

	saveState := func() {
		st := cloneState{Copied: copied, Parts: dst.parts}
		if b, err := json.Marshal(st); err == nil {
			tmp := statePath + ".tmp"
			if os.WriteFile(tmp, b, 0o600) == nil {
				_ = os.Rename(tmp, statePath)
			}
		}
	}

	for copied < srcSize {
		if err := ctx.Err(); err != nil {
			bw.Flush()
			dst.close()
			saveState()
			return CloneResult{}, err
		}
		n := chunk
		if remaining := srcSize - copied; n > remaining {
			n = remaining
		}
		// When splitting, never write past the current part's
		// capacity: roll first if the part is full, then cap the
		// write to the room that remains so parts are exact-sized.
		if dst.splitSize > 0 {
			room := dst.splitSize - dst.inPart
			if room <= 0 {
				if err := bw.Flush(); err != nil {
					dst.abort()
					return CloneResult{}, fmt.Errorf("disk: clone: flush: %w", err)
				}
				if err := dst.roll(); err != nil {
					dst.abort()
					return CloneResult{}, fmt.Errorf("disk: clone: roll: %w", err)
				}
				saveState()
				continue
			}
			if n > room {
				n = room
			}
		}
		rerr := readFullAt(src, buf[:n], copied)
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			// A chunk-level read error means part of it is bad.
			// Re-read sector by sector (512 B) so only the truly
			// unreadable sectors are logged and zero-filled — the
			// standard forensic "read error → fill, log, continue".
			bad += zeroBadSectors(src, buf[:n], copied, badLog)
		} else if errors.Is(rerr, io.EOF) {
			// Short source: the tail cannot be read; log it like a
			// bad sector and zero-fill so the clone length holds.
			bad++
			if badLog != nil {
				fmt.Fprintf(badLog, "%d\t%d\tEOF\n", copied, n)
			}
			for i := int64(0); i < n; i++ {
				buf[i] = 0
			}
		}
		if _, err := bw.Write(buf[:n]); err != nil {
			dst.abort()
			saveState()
			return CloneResult{}, fmt.Errorf("disk: clone: write: %w", err)
		}
		h.Write(buf[:n])
		copied += n
		if progress != nil {
			progress(CloneProgress{Copied: copied, Total: srcSize, BadSectors: bad, PartIndex: dst.partIndex})
		}
		// Flush when splitting so the on-disk part size (and the
		// roll threshold) tracks bytes that actually reached the file.
		if dst.splitSize > 0 {
			if err := bw.Flush(); err != nil {
				dst.abort()
				return CloneResult{}, fmt.Errorf("disk: clone: flush: %w", err)
			}
		}
	}
	if err := bw.Flush(); err != nil {
		dst.abort()
		return CloneResult{}, fmt.Errorf("disk: clone: flush: %w", err)
	}
	if err := dst.close(); err != nil {
		return CloneResult{}, fmt.Errorf("disk: clone: close: %w", err)
	}
	os.Remove(statePath) // finished: no resume needed

	srcSum := fmt.Sprintf("%x", h.Sum(nil))
	dstSum := ""
	if opts.Compression == CompressNone {
		dh, err := hashFiles(dst.parts)
		if err != nil {
			return CloneResult{}, fmt.Errorf("disk: clone: verify: %w", err)
		}
		dstSum = dh
		if dstSum != srcSum {
			return CloneResult{}, fmt.Errorf("disk: clone: destination hash mismatch (src %s, dst %s)", srcSum, dstSum)
		}
	}
	return CloneResult{
		DestPath:     dst.parts[0],
		Parts:        dst.parts,
		BytesCopied:  copied,
		BadSectors:   bad,
		SourceSHA256: srcSum,
		DestSHA256:   dstSum,
	}, nil
}

// readFullAt fills buf via successive ReadAt calls. It returns the
// first non-EOF error, or io.EOF if the source ended before filling
// buf.
func readFullAt(r io.ReaderAt, buf []byte, off int64) error {
	total := 0
	for total < len(buf) {
		n, err := r.ReadAt(buf[total:], off+int64(total))
		total += n
		if err != nil {
			if errors.Is(err, io.EOF) {
				return io.EOF
			}
			return err
		}
	}
	return nil
}

// zeroBadSectors re-reads [off, off+len(buf)) in 512-byte sectors,
// logging and zero-filling only the sectors that fail. It returns the
// number of bad sectors found. A failing whole-chunk read is the
// signal to call this; sector reads are the precision pass.
func zeroBadSectors(src io.ReaderAt, buf []byte, off int64, log *os.File) int64 {
	const sector = 512
	var bad int64
	for s := 0; s < len(buf); s += sector {
		end := s + sector
		if end > len(buf) {
			end = len(buf)
		}
		rerr := readFullAt(src, buf[s:end], off+int64(s))
		if rerr == nil || errors.Is(rerr, io.EOF) {
			if errors.Is(rerr, io.EOF) && s+sector < len(buf) {
				// EOF before the chunk ended: rest of the chunk is
				// unreadable; zero it and log once.
				for i := s; i < len(buf); i++ {
					buf[i] = 0
				}
				bad++
				if log != nil {
					fmt.Fprintf(log, "%d\t%d\tEOF\n", off+int64(s), len(buf)-s)
				}
				return bad
			}
			continue
		}
		bad++
		if log != nil {
			fmt.Fprintf(log, "%d\t%d\t%v\n", off+int64(s), end-s, rerr)
		}
		for i := s; i < end; i++ {
			buf[i] = 0
		}
	}
	return bad
}

// cloneDest owns the destination file(s) and the optional compressor,
// rolling to new part files when the split threshold is reached.
type cloneDest struct {
	f          *os.File
	zw         *zstd.Encoder
	gz         *gzip.Writer
	parts      []string
	partIndex  int
	splitSize  int64
	inPart     int64 // bytes written into the current part
	dstPattern string
	compress   string
}

func (d *cloneDest) Write(p []byte) (int, error) {
	var n int
	var err error
	switch {
	case d.zw != nil:
		n, err = d.zw.Write(p)
	case d.gz != nil:
		n, err = d.gz.Write(p)
	default:
		n, err = d.f.Write(p)
	}
	d.inPart += int64(n)
	return n, err
}

func (d *cloneDest) roll() error {
	if err := d.closeCurrent(); err != nil {
		return err
	}
	d.partIndex++
	name := fmt.Sprintf(d.dstPattern, d.partIndex)
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	d.f = f
	d.parts = append(d.parts, name)
	d.inPart = 0
	return nil
}

// closeCurrent closes the compressor (if any) and the current file.
func (d *cloneDest) closeCurrent() error {
	var first error
	if d.zw != nil {
		first = d.zw.Close()
		d.zw = nil
	}
	if d.gz != nil {
		if err := d.gz.Close(); first == nil {
			first = err
		}
		d.gz = nil
	}
	if d.f != nil {
		if err := d.f.Close(); first == nil {
			first = err
		}
		d.f = nil
	}
	return first
}

// close finishes the destination (compressor flush + file close).
func (d *cloneDest) close() error { return d.closeCurrent() }

// abort closes everything without flushing the compressor trailer —
// used on error paths where the output is known-incomplete.
func (d *cloneDest) abort() {
	d.zw = nil
	d.gz = nil
	if d.f != nil {
		d.f.Close()
		d.f = nil
	}
}

// open prepares the destination stream, honouring resume: the partial
// part is truncated back to the last verified offset and rewritten
// from there.
func (d *cloneDest) open(dstPattern string, opts CloneOptions, start int64, priorParts []string) error {
	d.dstPattern = dstPattern
	d.splitSize = opts.SplitSize
	d.compress = opts.Compression
	d.parts = append([]string{}, priorParts...)

	if opts.Compression == CompressNone && opts.SplitSize > 0 {
		// Work out which part `start` lives in and open it for
		// in-place rewrite of its tail.
		partIdx := 0
		offsetInPart := start
		if opts.Resume && start > 0 {
			partIdx = int(start / opts.SplitSize)
			offsetInPart = start % opts.SplitSize
		}
		for len(d.parts) <= partIdx {
			name := fmt.Sprintf(dstPattern, len(d.parts))
			f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				// Already exists (resume): open and truncate later.
				f, err = os.OpenFile(name, os.O_WRONLY, 0)
				if err != nil {
					return err
				}
			}
			d.parts = append(d.parts, name)
			if len(d.parts)-1 == partIdx {
				d.f = f
			} else {
				f.Close()
			}
		}
		d.partIndex = partIdx
		if d.f == nil {
			// priorParts already covered partIdx; reopen it.
			f, err := os.OpenFile(d.parts[partIdx], os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			d.f = f
		}
		_ = d.f.Truncate(offsetInPart)
		if _, err := d.f.Seek(offsetInPart, io.SeekStart); err != nil {
			d.f.Close()
			return err
		}
		d.inPart = offsetInPart
		return nil
	}

	// Single-file destination (possibly compressed).
	name := dstPattern
	if strings.Contains(name, "%d") {
		name = fmt.Sprintf(name, 0)
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if opts.Resume && start > 0 {
		flags = os.O_WRONLY | os.O_CREATE
	}
	f, err := os.OpenFile(name, flags, 0o644)
	if err != nil {
		return err
	}
	if opts.Resume && start > 0 {
		// Keep the verified prefix [0, start) and cut the incomplete
		// tail; writing then continues from `start`.
		_ = f.Truncate(start)
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			f.Close()
			return err
		}
	}
	d.f = f
	d.parts = append(d.parts, name)
	switch opts.Compression {
	case CompressGzip:
		d.gz = gzip.NewWriter(f)
	case CompressZstd:
		zw, err := zstd.NewWriter(f)
		if err != nil {
			f.Close()
			return err
		}
		d.zw = zw
	}
	return nil
}

// hashFiles returns the SHA-256 of the concatenation of parts.
func hashFiles(parts []string) (string, error) {
	h := sha256.New()
	buf := make([]byte, 1<<20)
	for _, p := range parts {
		if err := hashOne(h, p, buf); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func hashOne(h hash.Hash, path string, buf []byte) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if errors.Is(rerr, io.EOF) {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// AbsPath exposes the shared path normaliser to the service layer.
func AbsPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}
