package service

import (
	"bytes"
	"crypto/sha256"
	stdhex "encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testPNG(payload int) []byte {
	hdr := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	body := bytes.Repeat([]byte{'A'}, payload)
	return append(append(hdr, body...), 'I', 'E', 'N', 'D', 0xAE, 0x42, 0x60, 0x82)
}

func testJPEG(payload int) []byte {
	hdr := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00}
	body := bytes.Repeat([]byte{0x21}, payload)
	return append(append(hdr, body...), 0xFF, 0xD9)
}

func carveImage(t *testing.T) (string, int, int) {
	t.Helper()
	var data []byte
	data = append(data, bytes.Repeat([]byte{0x20}, 64)...)
	pngAt := len(data)
	data = append(data, testPNG(300)...)
	data = append(data, bytes.Repeat([]byte{0x20}, 64)...)
	jpegAt := len(data)
	data = append(data, testJPEG(300)...)
	return writeFile(t, "carve.bin", data), pngAt, jpegAt
}

func TestCarveTypes(t *testing.T) {
	app := newTestApp(t)
	list := app.CarveTypes()
	if len(list) == 0 {
		t.Fatal("CarveTypes() returned nothing")
	}
	for _, ti := range list {
		if ti.Name == "" || ti.Ext == "" || (ti.Extent != "footer" && ti.Extent != "length") {
			t.Errorf("incomplete type: %+v", ti)
		}
	}
}

func TestCarveScan(t *testing.T) {
	app := newTestApp(t)
	p, pngAt, jpegAt := carveImage(t)

	got, err := app.CarveScan(p, 0, 0, nil, 0, false)
	if err != nil {
		t.Fatalf("CarveScan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d results, want 2: %+v", len(got), got)
	}
	if got[0].Type != "png" || got[0].Offset != int64(pngAt) {
		t.Errorf("[0] = %s@%d, want png@%d", got[0].Type, got[0].Offset, pngAt)
	}
	if got[1].Type != "jpeg" || got[1].Offset != int64(jpegAt) {
		t.Errorf("[1] = %s@%d, want jpeg@%d", got[1].Type, got[1].Offset, jpegAt)
	}
	if want := int64(len(testPNG(300))); got[0].Length != want {
		t.Errorf("png length = %d, want %d", got[0].Length, want)
	}
}

func TestCarveScanRangeAndTypes(t *testing.T) {
	app := newTestApp(t)
	p, pngAt, _ := carveImage(t)

	// A range starting between the two objects must find only the JPEG.
	gap := int64(pngAt) + int64(len(testPNG(300))) + 10
	got, err := app.CarveScan(p, gap, 0, nil, 0, false)
	if err != nil {
		t.Fatalf("CarveScan: %v", err)
	}
	if len(got) != 1 || got[0].Type != "jpeg" {
		t.Fatalf("got %+v, want a single jpeg", got)
	}

	// Restricting the types drops the JPEG even though it is inside the range.
	got, err = app.CarveScan(p, 0, 0, []string{"png"}, 0, false)
	if err != nil {
		t.Fatalf("CarveScan: %v", err)
	}
	if len(got) != 1 || got[0].Type != "png" {
		t.Fatalf("got %+v, want a single png", got)
	}
}

func TestCarveScanLimits(t *testing.T) {
	app := newTestApp(t)
	p, _, _ := carveImage(t)

	got, err := app.CarveScan(p, 0, 0, nil, 1, false)
	if err != nil {
		t.Fatalf("CarveScan: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Max=1 gave %d results, want 1", len(got))
	}

	if _, err := app.CarveScan(p, 0, 0, []string{"nope"}, 0, false); err == nil {
		t.Error("unknown type = nil error, want error")
	}
	if _, err := app.CarveScan("", 0, 0, nil, 0, false); err == nil {
		t.Error("empty path = nil error, want error")
	}
	if _, err := app.CarveScan(filepath.Join(t.TempDir(), "missing.bin"), 0, 0, nil, 0, false); err == nil {
		t.Error("missing file = nil error, want error")
	}
}

func TestCarveExport(t *testing.T) {
	app := newTestApp(t)
	p, pngAt, _ := carveImage(t)

	got, err := app.CarveScan(p, 0, 0, []string{"png"}, 0, false)
	if err != nil {
		t.Fatalf("CarveScan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 png, got %d", len(got))
	}
	want := testPNG(300)
	if got[0].Offset != int64(pngAt) || got[0].Length != int64(len(want)) {
		t.Fatalf("got %#x+%d, want %#x+%d", got[0].Offset, got[0].Length, pngAt, len(want))
	}

	dst := filepath.Join(t.TempDir(), "recovered.png")
	res, err := app.CarveExport(p, got[0], dst)
	if err != nil {
		t.Fatalf("CarveExport: %v", err)
	}
	if res.Path != dst || res.BytesSaved != int64(len(want)) || res.Mode != "carve" {
		t.Errorf("result = %+v, want path %s, %d bytes, mode carve", res, dst, len(want))
	}
	sum := sha256.Sum256(want)
	if res.SHA256 != stdhex.EncodeToString(sum[:]) {
		t.Errorf("SHA256 = %s, want %s", res.SHA256, stdhex.EncodeToString(sum[:]))
	}
	out, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, want) {
		t.Errorf("exported %d bytes, content mismatch", len(out))
	}

	// Both the scan and the export must be recorded.
	logged, err := os.ReadFile(app.cfg.AuditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), `"carve"`) {
		t.Errorf("audit log has no carve entries:\n%s", logged)
	}
}

func TestCarveExportErrors(t *testing.T) {
	app := newTestApp(t)
	p, _, _ := carveImage(t)
	got, err := app.CarveScan(p, 0, 0, []string{"png"}, 0, false)
	if err != nil {
		t.Fatalf("CarveScan: %v", err)
	}
	item := got[0]

	t.Run("destination exists", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "taken.png")
		if err := os.WriteFile(dst, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := app.CarveExport(p, item, dst); err == nil {
			t.Error("overwrite = nil error, want error")
		}
	})
	t.Run("invalid range", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "bad.png")
		if _, err := app.CarveExport(p, item, ""); err == nil {
			t.Error("empty destination = nil error, want error")
		}
		if _, err := app.CarveExport("", item, dst); err == nil {
			t.Error("empty source = nil error, want error")
		}
		if _, err := app.CarveExport(p, item, dst+"-0"); err != nil {
			t.Errorf("valid export failed: %v", err)
		}
		bad := item
		bad.Length = 0
		if _, err := app.CarveExport(p, bad, dst); err == nil {
			t.Error("zero length = nil error, want error")
		}
		bad = item
		bad.Offset = -1
		if _, err := app.CarveExport(p, bad, dst); err == nil {
			t.Error("negative offset = nil error, want error")
		}
	})
	t.Run("range past the source", func(t *testing.T) {
		bad := item
		bad.Length = 1 << 30
		dst := filepath.Join(t.TempDir(), "huge.png")
		if _, err := app.CarveExport(p, bad, dst); err == nil {
			t.Error("range past the source = nil error, want error")
		}
		if _, statErr := os.Stat(dst); statErr == nil {
			t.Error("destination left behind after a failed export")
		}
	})
}
