package service

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IshikawaUta/gohex/internal/audit"
)

func TestExportViewPDFAndPNG(t *testing.T) {
	app := newTestApp(t)
	src := writeFile(t, "view.bin", []byte("Hello, GoHex print export! 0123456789abcdef"))
	id, err := app.OpenFile(src)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.CloseDocument(id.ID) })

	dir := t.TempDir()
	pdfPath := filepath.Join(dir, "view.pdf")
	res, err := app.ExportView(id.ID, 0, 47, pdfPath)
	if err != nil {
		t.Fatalf("PDF export: %v", err)
	}
	if res.SHA256 == "" || res.BytesSaved == 0 {
		t.Errorf("res = %+v", res)
	}
	pdf, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-1.4")) || !bytes.Contains(pdf, []byte("48 65 6c 6c 6f")) {
		t.Error("PDF is missing the hex grid")
	}

	pngPath := filepath.Join(dir, "view.png")
	if _, err := app.ExportView(id.ID, 0, 47, pngPath); err != nil {
		t.Fatalf("PNG export: %v", err)
	}
	png, err := os.ReadFile(pngPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(png, []byte("\x89PNG")) {
		t.Error("PNG magic missing")
	}

	// Unsupported extension refuses; destination untouched.
	if _, err := app.ExportView(id.ID, 0, 16, filepath.Join(dir, "view.bmp")); err == nil {
		t.Error(".bmp must be refused")
	}

	// Oversize range refuses before reading.
	if _, err := app.ExportView(id.ID, 0, 4001*16, filepath.Join(dir, "big.pdf")); err == nil {
		t.Error("oversize range must be refused")
	}

	// O_EXCL: existing destination refuses.
	if _, err := app.ExportView(id.ID, 0, 16, pdfPath); err == nil {
		t.Error("existing destination must be refused")
	}

	events, err := audit.ReadAll(app.log.Path(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var ok, failed bool
	for _, e := range events {
		if e.Detail["op"] != "export-view" {
			continue
		}
		if e.Target == pdfPath && e.Result == audit.ResultOK {
			ok = true
		}
		if e.Result == audit.ResultError {
			failed = true
		}
	}
	if !ok || !failed {
		t.Errorf("audit trail incomplete: ok=%v failed=%v", ok, failed)
	}

	// The audit line for a successful export carries the hash.
	for _, e := range events {
		if e.Detail["op"] == "export-view" && e.Result == audit.ResultOK {
			if !strings.HasPrefix(e.Hash, "sha256:") {
				t.Errorf("hash = %q", e.Hash)
			}
		}
	}
}
