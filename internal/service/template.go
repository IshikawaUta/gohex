package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/template"
)

// maxTemplateSize caps a template source file (1 MiB — far above any
// real structure definition).
const maxTemplateSize = 1 << 20

// TemplateField is one field of a parsed template, for the GUI's field
// table.
type TemplateField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Offset      int64  `json:"offset"`
	Count       int    `json:"count"`
	Size        int64  `json:"size"`
	Description string `json:"description,omitempty"`
}

// TemplateInfo is the JSON-serialisable snapshot of a parsed template.
type TemplateInfo struct {
	Path      string          `json:"path"`
	Name      string          `json:"name"`
	Comment   string          `json:"comment,omitempty"`
	Size      int64           `json:"size"`
	BigEndian bool            `json:"bigEndian"`
	Fields    []TemplateField `json:"fields"`
}

// TemplateLoad parses a template file (WinHex-style key=value structure
// definition) and returns its field table. The read is recorded in the
// audit log; nothing is applied to any document yet.
func (a *App) TemplateLoad(path string) (TemplateInfo, error) {
	if path == "" {
		return TemplateInfo{}, errors.New("service: template: empty path")
	}
	abs := absPath(path)
	tpl, err := parseTemplateFile(abs)
	if err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionOpen,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "template", "error": err.Error()},
		})
		return TemplateInfo{}, err
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionOpen,
		Target: abs,
		Result: audit.ResultOK,
		Detail: map[string]string{
			"op":     "template",
			"fields": fmt.Sprintf("%d", len(tpl.Fields)),
			"mode":   "read-only",
		},
	})
	info := TemplateInfo{
		Path:      abs,
		Name:      tpl.Name,
		Comment:   tpl.Comment,
		Size:      tpl.Size,
		BigEndian: tpl.BigEndian,
		Fields:    make([]TemplateField, 0, len(tpl.Fields)),
	}
	for _, f := range tpl.Fields {
		info.Fields = append(info.Fields, TemplateField{
			Name:        f.Name,
			Type:        string(f.Type),
			Offset:      f.Offset,
			Count:       f.Count,
			Size:        f.Size,
			Description: f.Description,
		})
	}
	return info, nil
}

// TemplateApply overlays the template file on an open document at the
// given absolute offset and returns every field's decoded value. The
// whole template span must be readable; a template that runs past the
// end of the document is an error, not a half-filled table. Each apply
// re-reads the template file (recorded in the audit log as
// "template-apply"); reading the open document itself needs no extra
// record, exactly like the search bar.
func (a *App) TemplateApply(path string, id int64, offset int64) ([]template.Value, error) {
	if path == "" {
		return nil, errors.New("service: template: empty path")
	}
	abs := absPath(path)
	d, err := a.lookup(id)
	if err != nil {
		return nil, err
	}
	tpl, err := parseTemplateFile(abs)
	if err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionOpen,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "template-apply", "error": err.Error()},
		})
		return nil, err
	}
	vals, err := tpl.Apply(d.document, offset)
	if err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionOpen,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{
				"op":     "template-apply",
				"doc":    fmt.Sprintf("%d", id),
				"offset": fmt.Sprintf("%d", offset),
				"error":  err.Error(),
			},
		})
		return nil, err
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionOpen,
		Target: abs,
		Result: audit.ResultOK,
		Detail: map[string]string{
			"op":     "template-apply",
			"doc":    fmt.Sprintf("%d", id),
			"offset": fmt.Sprintf("%d", offset),
			"mode":   "read-only",
		},
	})
	return vals, nil
}

// parseTemplateFile reads and parses one template file with the size cap.
func parseTemplateFile(abs string) (*template.Template, error) {
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("service: template: %w", err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("service: template: %q is a directory", filepath.Base(abs))
	}
	if fi.Size() > maxTemplateSize {
		return nil, fmt.Errorf("service: template %q is %d bytes (limit %d)",
			filepath.Base(abs), fi.Size(), maxTemplateSize)
	}
	src, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("service: template: %w", err)
	}
	tpl, err := template.Parse(src)
	if err != nil {
		return nil, fmt.Errorf("service: template: %w", err)
	}
	return tpl, nil
}
