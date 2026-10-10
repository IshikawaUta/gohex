package core

import (
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// writeBenchFile materialises a deterministic image of size bytes in the
// benchmark's temp directory. Random content is used so the kernel cannot
// collapse the file onto a shared zero page.
func writeBenchFile(tb testing.TB, size int64) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "raw.img")
	f, err := os.Create(path)
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()
	rnd := rand.New(rand.NewSource(0xC0FFEE))
	buf := make([]byte, 1<<20)
	remaining := size
	for remaining > 0 {
		n := int64(len(buf))
		if n > remaining {
			n = remaining
		}
		rnd.Read(buf[:n])
		if _, err := f.Write(buf[:n]); err != nil {
			tb.Fatal(err)
		}
		remaining -= n
	}
	if err := f.Sync(); err != nil {
		tb.Fatal(err)
	}
	return path
}

// benchSector is the logical sector size every parser in the tree assumes.
const benchSector = 512

// BenchmarkSequentialSectorRead reads a 32 MiB raw image one 512-byte sector
// at a time — the partition-table and filesystem parsers' access pattern.
func BenchmarkSequentialSectorRead(b *testing.B) {
	const total = 32 << 20
	path := writeBenchFile(b, total)
	src, err := OpenFile(path)
	if err != nil {
		b.Fatal(err)
	}
	defer src.Close()

	buf := make([]byte, benchSector)
	b.SetBytes(benchSector)
	off := int64(0)
	for i := 0; i < b.N; i++ {
		if n, err := src.ReadAt(buf, off); n != benchSector || (err != nil && off+benchSector < total) {
			b.Fatalf("read at %d: n=%d err=%v", off, n, err)
		}
		off += benchSector
		if off+benchSector > total {
			off = 0
		}
	}
}

// BenchmarkReadWindow4KiB walks the same image through ReadWindow, the
// bounded helper the GUI panels use, to compare against raw ReadAt.
func BenchmarkReadWindow4KiB(b *testing.B) {
	const total = 32 << 20
	path := writeBenchFile(b, total)
	src, err := OpenFile(path)
	if err != nil {
		b.Fatal(err)
	}
	defer src.Close()

	b.SetBytes(4 << 10)
	off := int64(0)
	for i := 0; i < b.N; i++ {
		if _, err := ReadWindow(src, off, 4<<10); err != nil {
			b.Fatal(err)
		}
		off += 4 << 10
		if off+4<<10 > total {
			off = 0
		}
	}
}
