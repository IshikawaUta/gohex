package disk

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errReaderAt simulates a source with unreadable (bad) sectors: reads
// fail with a non-EOF error inside [badStart, badEnd).
type errReaderAt struct {
	data    []byte
	badFrom int64
	badTo   int64
}

func (e *errReaderAt) ReadAt(p []byte, off int64) (int, error) {
	// Any read whose range intersects the bad region fails, like a
	// real block device returning EIO for a bad sector.
	if off < e.badTo && off+int64(len(p)) > e.badFrom {
		return 0, os.ErrDeadlineExceeded
	}
	if off >= int64(len(e.data)) {
		return 0, io.EOF
	}
	n := copy(p, e.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestClonePlain(t *testing.T) {
	dir := t.TempDir()
	srcData := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB
	src := bytes.NewReader(srcData)
	dst := filepath.Join(dir, "clone.bin")
	var last CloneProgress
	res, err := Clone(context.Background(), src, int64(len(srcData)), dst, CloneOptions{}, func(p CloneProgress) { last = p })
	if err != nil {
		t.Fatal(err)
	}
	if res.BytesCopied != int64(len(srcData)) {
		t.Errorf("copied = %d", res.BytesCopied)
	}
	if res.BadSectors != 0 {
		t.Errorf("bad = %d", res.BadSectors)
	}
	if res.SourceSHA256 != res.DestSHA256 {
		t.Errorf("hash mismatch src=%s dst=%s", res.SourceSHA256, res.DestSHA256)
	}
	body, _ := os.ReadFile(dst)
	if !bytes.Equal(body, srcData) {
		t.Error("destination content differs")
	}
	if last.Copied != int64(len(srcData)) {
		t.Errorf("progress final = %d", last.Copied)
	}
	// No state file left behind.
	if _, err := os.Stat(dst + ".clone-state.json"); !os.IsNotExist(err) {
		t.Error("state file survived a completed clone")
	}
}

func TestCloneGzipZstd(t *testing.T) {
	for _, comp := range []string{CompressGzip, CompressZstd} {
		dir := t.TempDir()
		srcData := bytes.Repeat([]byte{0x00}, 1<<16) // highly compressible
		dst := filepath.Join(dir, "clone."+comp)
		res, err := Clone(context.Background(), bytes.NewReader(srcData), int64(len(srcData)), dst, CloneOptions{Compression: comp}, nil)
		if err != nil {
			t.Fatalf("%s: %v", comp, err)
		}
		if res.DestSHA256 != "" {
			t.Errorf("%s: compressed clones skip verify, got %q", comp, res.DestSHA256)
		}
		body, _ := os.ReadFile(dst)
		if len(body) == 0 || len(body) >= len(srcData) {
			t.Errorf("%s: not compressed (%d → %d)", comp, len(srcData), len(body))
		}
	}
}

func TestCloneSplit(t *testing.T) {
	dir := t.TempDir()
	srcData := make([]byte, 10_000)
	for i := range srcData {
		srcData[i] = byte(i)
	}
	pattern := filepath.Join(dir, "part-%d.bin")
	res, err := Clone(context.Background(), bytes.NewReader(srcData), int64(len(srcData)), pattern, CloneOptions{SplitSize: 4096}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Parts) != 3 {
		t.Fatalf("parts = %v", res.Parts)
	}
	// Reassemble and compare.
	var joined []byte
	for _, p := range res.Parts {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		joined = append(joined, b...)
	}
	if !bytes.Equal(joined, srcData) {
		t.Error("reassembled parts differ from source")
	}
	if res.SourceSHA256 != res.DestSHA256 {
		t.Error("split clone hash mismatch")
	}
}

func TestCloneBadSectors(t *testing.T) {
	dir := t.TempDir()
	srcData := bytes.Repeat([]byte("A"), 8192)
	src := &errReaderAt{data: srcData, badFrom: 1024, badTo: 2048}
	dst := filepath.Join(dir, "clone.bin")
	logPath := filepath.Join(dir, "bad.log")
	res, err := Clone(context.Background(), src, int64(len(srcData)), dst, CloneOptions{BadSectorLog: logPath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.BadSectors == 0 {
		t.Error("no bad sectors reported")
	}
	body, _ := os.ReadFile(dst)
	if len(body) != len(srcData) {
		t.Fatalf("length = %d", len(body))
	}
	// The bad range must be zero-filled, the rest must be source data.
	if !bytes.Equal(body[:1024], srcData[:1024]) {
		t.Error("good prefix corrupted")
	}
	if !bytes.Equal(body[1024:2048], make([]byte, 1024)) {
		t.Error("bad range not zero-filled")
	}
	if !bytes.Equal(body[2048:], srcData[2048:]) {
		t.Error("good suffix corrupted")
	}
	logBody, _ := os.ReadFile(logPath)
	if !strings.Contains(string(logBody), "1024") {
		t.Errorf("bad-sector log missing range:\n%s", logBody)
	}
}

func TestCloneResume(t *testing.T) {
	dir := t.TempDir()
	// Multi-chunk source so a mid-run cancel leaves work undone.
	srcData := bytes.Repeat([]byte("resume-me-please!!"), 200_000) // ~3.6 MiB
	pattern := filepath.Join(dir, "part-%d.bin")
	// First run: cancel after the first progress callback.
	ctx, cancel := context.WithCancel(context.Background())
	count := 0
	_, err := Clone(ctx, bytes.NewReader(srcData), int64(len(srcData)), pattern, CloneOptions{SplitSize: 1 << 20}, func(p CloneProgress) {
		count++
		if count == 1 {
			cancel()
		}
	})
	if err == nil {
		t.Fatal("cancelled clone reported success")
	}
	// State file must exist for resume (%d is replaced with "state",
	// so "part-%d.bin" → "part-state.bin.clone-state.json").
	statePath := filepath.Join(dir, "part-state.bin.clone-state.json")
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state file missing: %v", err)
	}
	// Second run with Resume completes the job.
	res, err := Clone(context.Background(), bytes.NewReader(srcData), int64(len(srcData)), pattern, CloneOptions{SplitSize: 1 << 20, Resume: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.BytesCopied != int64(len(srcData)) {
		t.Errorf("resumed copied = %d", res.BytesCopied)
	}
	var joined []byte
	for _, p := range res.Parts {
		b, _ := os.ReadFile(p)
		joined = append(joined, b...)
	}
	if !bytes.Equal(joined, srcData) {
		t.Error("resumed clone differs from source")
	}
	if res.SourceSHA256 != res.DestSHA256 {
		t.Error("resumed clone hash mismatch")
	}
}

func TestCloneRejects(t *testing.T) {
	dir := t.TempDir()
	// Split + compression is invalid.
	if _, err := Clone(context.Background(), bytes.NewReader(nil), 0, filepath.Join(dir, "x-%d"), CloneOptions{Compression: CompressGzip, SplitSize: 1}, nil); err == nil {
		t.Error("split+gzip accepted")
	}
	// Split pattern without %d is invalid.
	if _, err := Clone(context.Background(), bytes.NewReader(nil), 0, filepath.Join(dir, "x.bin"), CloneOptions{SplitSize: 1}, nil); err == nil {
		t.Error("split without placeholder accepted")
	}
	// Unknown compression.
	if _, err := Clone(context.Background(), bytes.NewReader(nil), 0, filepath.Join(dir, "x.bin"), CloneOptions{Compression: "lzma"}, nil); err == nil {
		t.Error("unknown compression accepted")
	}
	// Negative size.
	if _, err := Clone(context.Background(), bytes.NewReader(nil), -1, filepath.Join(dir, "x.bin"), CloneOptions{}, nil); err == nil {
		t.Error("negative size accepted")
	}
}
