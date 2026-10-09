package service

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/IshikawaUta/gohex/internal/audit"
)

const testTemplate = `
Template=Mini DOS Header
Comment=test

Offset=0
Type=u16
Name=e_magic

Offset=2
Type=u16[2]
Name=e_cblp

Offset=6
Type=string[4]
Name=tag
`

func TestTemplateLoadApply(t *testing.T) {
	app := newTestApp(t)

	data := make([]byte, 16)
	binary.LittleEndian.PutUint16(data[0:2], 0x5A4D) // "MZ"
	binary.LittleEndian.PutUint16(data[2:4], 0x0090)
	binary.LittleEndian.PutUint16(data[4:6], 0x0003)
	copy(data[6:10], "GoHX")

	doc, err := app.OpenFile(writeFile(t, "evidence.bin", data))
	if err != nil {
		t.Fatal(err)
	}
	tpath := writeFile(t, "dos.tpl", []byte(testTemplate))

	info, err := app.TemplateLoad(tpath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "Mini DOS Header" || info.Comment != "test" {
		t.Fatalf("meta = %q %q", info.Name, info.Comment)
	}
	if info.Size != 10 || len(info.Fields) != 3 {
		t.Fatalf("size/fields = %d %d", info.Size, len(info.Fields))
	}
	if info.Fields[1].Type != "u16" || info.Fields[1].Count != 2 {
		t.Errorf("field1 = %+v", info.Fields[1])
	}

	vals, err := app.TemplateApply(tpath, doc.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 3 {
		t.Fatalf("values = %d", len(vals))
	}
	if vals[0].Display != "0x5a4d (23117)" {
		t.Errorf("e_magic = %q", vals[0].Display)
	}
	if vals[1].Display != "0x0090 (144)  0x0003 (3)" {
		t.Errorf("e_cblp = %q", vals[1].Display)
	}
	if vals[2].Display != "\"GoHX\"" {
		t.Errorf("tag = %q", vals[2].Display)
	}

	// Apply at a non-zero base inside the document.
	vals, err = app.TemplateApply(tpath, doc.ID, 6)
	if err != nil {
		t.Fatal(err)
	}
	if vals[0].Offset != 6 || !strings.Contains(vals[0].Display, "0x6f47") {
		t.Errorf("base apply: %+v", vals[0])
	}

	events, err := audit.ReadAll(app.log.Path(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var loads, applies int
	for _, e := range events {
		if e.Action != audit.ActionOpen || e.Target != tpath {
			continue
		}
		switch e.Detail["op"] {
		case "template":
			loads++
		case "template-apply":
			applies++
		}
	}
	if loads < 1 || applies < 2 {
		t.Errorf("audit: loads=%d applies=%d", loads, applies)
	}
}

func TestTemplateErrors(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.TemplateLoad(""); err == nil {
		t.Error("empty path: err = nil")
	}
	if _, err := app.TemplateLoad("/nonexistent/x.tpl"); err == nil {
		t.Error("missing file: err = nil")
	}
	if _, err := app.TemplateLoad(t.TempDir()); err == nil {
		t.Error("directory: err = nil")
	}
	big := writeFile(t, "big.tpl", bytes.Repeat([]byte("#"), maxTemplateSize+1))
	if _, err := app.TemplateLoad(big); err == nil {
		t.Error("oversized template: err = nil")
	}
	bad := writeFile(t, "bad.tpl", []byte("Template=T\nOffset=0\nType=widget\nName=x\n"))
	if _, err := app.TemplateLoad(bad); err == nil {
		t.Error("bad template: err = nil")
	} else if !strings.Contains(err.Error(), "unknown field type") {
		t.Errorf("err = %v", err)
	}

	doc := app.NewDocument() // empty document
	good := writeFile(t, "good.tpl", []byte(testTemplate))
	if _, err := app.TemplateApply("", doc.ID, 0); err == nil {
		t.Error("apply empty path: err = nil")
	}
	if _, err := app.TemplateApply(good, 999, 0); err == nil {
		t.Error("apply unknown doc: err = nil")
	}
	if _, err := app.TemplateApply(good, doc.ID, 0); err == nil {
		t.Error("apply past end of empty doc: err = nil")
	} else if !strings.Contains(err.Error(), "only 0 readable") {
		t.Errorf("err = %v, want truncation message", err)
	}
	// Oversized apply on a doc that is too small for the template.
	small, err := app.OpenFile(writeFile(t, "tiny.bin", []byte{1, 2}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.TemplateApply(good, small.ID, 0); err == nil {
		t.Error("apply truncated: err = nil")
	}
	if _, err := app.TemplateApply(good, small.ID, -1); err == nil {
		t.Error("apply negative offset: err = nil")
	}
}
