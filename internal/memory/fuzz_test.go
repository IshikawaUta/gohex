package memory

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzOpen drives the memory-capture format detector and every parser it can
// dispatch to (LiME, AVML, ELF core, minidump, Windows dumps, raw fallback).
// The capture is written to a temp file because Open works on a path.
func FuzzOpen(f *testing.F) {
	region := memRegion{addr: 0x400000, data: payloadFor(0x400000, 64)}
	f.Add([]byte{})
	f.Add([]byte("plain raw capture bytes"))
	f.Add([]byte("not a dump, just prose\x00\x01\x02"))
	f.Add(limeBlock(0x1000, 0x103F))
	f.Add(avmlBlock(0x1000, 0x103F, payloadFor(0x1000, 64)))
	f.Add(buildELFCore([]memRegion{region}))
	f.Add(buildMinidump64([]memRegion{region}))
	f.Add(buildWinDumpFull([]winRun{{basePage: 0, pages: 1}}, payloadFor(0, 4096)))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("input too large")
		}
		path := filepath.Join(t.TempDir(), "capture.bin")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		cap, err := Open(path)
		if err != nil {
			return
		}
		// A recognised capture must at least have a consistent segment map.
		var total int64
		for _, s := range cap.Segments {
			if s.Length < 0 {
				t.Fatalf("negative segment length %d", s.Length)
			}
			total += s.Length
		}
		_, _ = cap.Locate(int64(total / 2))
	})
}
