package service

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// writeRaid5Members builds two data members + one XOR parity member
// from data (padded to whole 8-byte stripes) and writes them out.
func writeRaid5Members(t *testing.T, dir string, data []byte) []string {
	t.Helper()
	const stripe = 8
	for len(data)%(stripe*2) != 0 {
		data = append(data, 0)
	}
	d0 := make([]byte, len(data)/2)
	d1 := make([]byte, len(data)/2)
	p := make([]byte, len(data)/2)
	for s := 0; s*stripe*2 < len(data); s++ {
		off := s * stripe
		copy(d0[off:], data[s*stripe*2:s*stripe*2+stripe])
		copy(d1[off:], data[s*stripe*2+stripe:s*stripe*2+2*stripe])
		for i := 0; i < stripe; i++ {
			p[off+i] = d0[off+i] ^ d1[off+i]
		}
	}
	var paths []string
	for i, b := range [][]byte{d0, d1, p} {
		fp := filepath.Join(dir, "member"+string(rune('0'+i))+".bin")
		if err := os.WriteFile(fp, b, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, fp)
	}
	return paths
}

func TestRaidOpenAndRead(t *testing.T) {
	app := newTestApp(t)
	dir := t.TempDir()
	data := []byte("forensic raid volume contents for testing!!")
	for len(data)%16 != 0 {
		data = append(data, 0) // pad to whole 8×2 stripes
	}
	paths := writeRaid5Members(t, dir, data)
	doc, err := app.RaidOpen(paths, "5", 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer app.CloseDocument(doc.ID)
	if doc.Size != int64(len(data)) {
		t.Fatalf("doc size = %d, want %d", doc.Size, len(data))
	}
	w, err := app.ReadWindow(doc.ID, 0, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.Bytes, data) {
		t.Errorf("read:\n got %q\nwant %q", w.Bytes, data)
	}
}

func TestRaidOpenDegraded(t *testing.T) {
	app := newTestApp(t)
	dir := t.TempDir()
	data := []byte("degraded raid5 volume contents for test....")
	for len(data)%16 != 0 {
		data = append(data, 0)
	}
	paths := writeRaid5Members(t, dir, data)
	// Mark member 0 missing; reads must reconstruct via parity.
	doc, err := app.RaidOpen(paths, "5", 8, []int{0})
	if err != nil {
		t.Fatal(err)
	}
	defer app.CloseDocument(doc.ID)
	w, err := app.ReadWindow(doc.ID, 0, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.Bytes, data) {
		t.Errorf("degraded read:\n got %q\nwant %q", w.Bytes, data)
	}
}

func TestRaidOpenValidation(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.RaidOpen(nil, "5", 512, nil); err == nil {
		t.Error("no members accepted")
	}
	if _, err := app.RaidOpen([]string{"x"}, "10", 512, nil); err == nil {
		t.Error("bad level accepted")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "m.bin")
	os.WriteFile(p, make([]byte, 100), 0o644)
	if _, err := app.RaidOpen([]string{p, filepath.Join(dir, "missing")}, "0", 512, nil); err == nil {
		t.Error("missing member accepted")
	}
	if _, err := app.RaidOpen([]string{p, p}, "6", 512, nil); err == nil {
		t.Error("RAID6 with 2 members accepted")
	}
	// All members marked missing.
	if _, err := app.RaidOpen([]string{p, p}, "1", 512, []int{0, 1}); err == nil {
		t.Error("all-missing accepted")
	}
}
