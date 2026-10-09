// Package template overlays named structure definitions on evidence —
// the "template" workflow familiar from WinHex: a flat list of typed
// fields at fixed offsets, applied to an open document at a chosen base
// offset.
//
// Template files are plain key=value text (WinHex-compatible shape):
//
//	Template=DOS Header
//	Comment=First 64 bytes of a PE file
//
//	Offset=0
//	Type=u16
//	Name=e_magic
//
//	Offset=2
//	Type=u16[3]
//	Name=e_cblp_e_cp
//
// Each Offset= line starts a new field; Type and Name are required per
// field, Count and Description are optional. Type accepts the base
// names below with an optional [N] array suffix (or a separate Count=
// key). Endian=little (default) or big selects multi-byte byte order
// for the whole template. Parsing is strict: an unknown key, an unknown
// type or a missing name is an error, never a silently skipped field.
package template

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// FieldType is the interpretation of one template field.
type FieldType string

// The field types a template may use.
const (
	TypeU8  FieldType = "u8"
	TypeU16 FieldType = "u16"
	TypeU32 FieldType = "u32"
	TypeU64 FieldType = "u64"
	TypeI8  FieldType = "i8"
	TypeI16 FieldType = "i16"
	TypeI32 FieldType = "i32"
	TypeI64 FieldType = "i64"
	TypeF32 FieldType = "f32"
	TypeF64 FieldType = "f64"

	TypeBytes    FieldType = "bytes"    // Count raw bytes, hex display
	TypeString   FieldType = "string"   // Count raw bytes, text display
	TypeChar     FieldType = "char"     // alias of string
	TypeGUID     FieldType = "guid"     // 16 bytes, Microsoft GUID layout
	TypeFiletime FieldType = "filetime" // u64, Windows FILETIME
	TypeUnixTime FieldType = "unixtime" // u32 seconds since the Unix epoch
	TypeBool8    FieldType = "bool8"
	TypeBool16   FieldType = "bool16"
	TypeBool32   FieldType = "bool32"
)

// Field is one named field of a template.
type Field struct {
	Name        string    `json:"name"`
	Type        FieldType `json:"type"`
	Count       int       `json:"count"` // array length; always >= 1
	Offset      int64     `json:"offset"`
	Size        int64     `json:"size"` // Count * unit size
	Description string    `json:"description,omitempty"`
}

// Template is a parsed template file: a flat, offset-addressed field
// list sorted by offset.
type Template struct {
	Name      string  `json:"name"`
	Comment   string  `json:"comment,omitempty"`
	BigEndian bool    `json:"bigEndian"`
	Fields    []Field `json:"fields"`
	Size      int64   `json:"size"` // span from offset 0 to the last byte
}

// Value is one field's result after being applied to data.
type Value struct {
	Name    string `json:"name"`
	Offset  int64  `json:"offset"` // absolute: base + field offset
	Type    string `json:"type"`
	Display string `json:"display"`
	Raw     []byte `json:"raw,omitempty"`
}

// unitSize returns the byte width of one element of t.
func unitSize(t FieldType) (int64, error) {
	switch t {
	case TypeU8, TypeI8, TypeBool8, TypeChar, TypeString, TypeBytes:
		return 1, nil
	case TypeU16, TypeI16, TypeBool16:
		return 2, nil
	case TypeU32, TypeI32, TypeBool32, TypeF32, TypeUnixTime:
		return 4, nil
	case TypeU64, TypeI64, TypeF64, TypeFiletime:
		return 8, nil
	case TypeGUID:
		return 16, nil
	}
	return 0, fmt.Errorf("unknown field type %q", t)
}

// normalizeType maps aliases onto the canonical type names.
func normalizeType(name string) (FieldType, error) {
	t := FieldType(strings.ToLower(strings.TrimSpace(name)))
	switch t {
	case "byte":
		return TypeU8, nil
	case "word", "ushort", "uint16":
		return TypeU16, nil
	case "dword", "uint32":
		return TypeU32, nil
	case "qword", "uint64":
		return TypeU64, nil
	case "int8":
		return TypeI8, nil
	case "int16", "short":
		return TypeI16, nil
	case "int32", "int":
		return TypeI32, nil
	case "int64", "long":
		return TypeI64, nil
	case "float", "float32":
		return TypeF32, nil
	case "double", "float64":
		return TypeF64, nil
	}
	if _, err := unitSize(t); err != nil {
		return "", err
	}
	return t, nil
}

// parseType splits "u32[4]" into ("u32", 4).
func parseType(raw string) (FieldType, int, error) {
	name, count := raw, 1
	if i := strings.IndexByte(raw, '['); i >= 0 {
		if !strings.HasSuffix(raw, "]") {
			return "", 0, fmt.Errorf("malformed array type %q", raw)
		}
		name = raw[:i]
		n, err := strconv.Atoi(raw[i+1 : len(raw)-1])
		if err != nil || n <= 0 {
			return "", 0, fmt.Errorf("malformed array count in %q", raw)
		}
		count = n
	}
	t, err := normalizeType(name)
	if err != nil {
		return "", 0, err
	}
	return t, count, nil
}

// Parse reads a template file's contents.
func Parse(src []byte) (*Template, error) {
	t := &Template{}
	var cur *Field
	flush := func(lineno int) error {
		if cur == nil {
			return nil
		}
		if cur.Name == "" {
			return fmt.Errorf("template: field at line %d has no Name", lineno)
		}
		us, err := unitSize(cur.Type)
		if err != nil {
			return fmt.Errorf("template: field %q: %w", cur.Name, err)
		}
		if cur.Count <= 0 {
			return fmt.Errorf("template: field %q: Count must be >= 1", cur.Name)
		}
		cur.Size = us * int64(cur.Count)
		t.Fields = append(t.Fields, *cur)
		cur = nil
		return nil
	}

	for i, raw := range strings.Split(string(src), "\n") {
		lineno := i + 1
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("template: line %d: want key=value, got %q", lineno, line)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "template":
			if val == "" {
				return nil, fmt.Errorf("template: line %d: empty Template name", lineno)
			}
			t.Name = val
		case "comment":
			t.Comment = val
		case "endian":
			switch strings.ToLower(val) {
			case "big", "be":
				t.BigEndian = true
			case "little", "le", "":
			default:
				return nil, fmt.Errorf("template: line %d: unknown endian %q", lineno, val)
			}
		case "offset":
			if err := flush(lineno); err != nil {
				return nil, err
			}
			n, err := strconv.ParseInt(val, 0, 64)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("template: line %d: bad offset %q", lineno, val)
			}
			cur = &Field{Offset: n}
		case "type":
			if cur == nil {
				return nil, fmt.Errorf("template: line %d: Type before any Offset", lineno)
			}
			if cur.Type != "" {
				return nil, fmt.Errorf("template: line %d: duplicate Type for field at offset %d", lineno, cur.Offset)
			}
			ft, count, err := parseType(val)
			if err != nil {
				return nil, fmt.Errorf("template: line %d: %w", lineno, err)
			}
			cur.Type, cur.Count = ft, count
		case "count":
			if cur == nil {
				return nil, fmt.Errorf("template: line %d: Count before any Offset", lineno)
			}
			n, err := strconv.Atoi(val)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("template: line %d: bad Count %q", lineno, val)
			}
			cur.Count = n
		case "name":
			if cur == nil {
				return nil, fmt.Errorf("template: line %d: Name before any Offset", lineno)
			}
			if cur.Name != "" {
				return nil, fmt.Errorf("template: line %d: duplicate Name for field at offset %d", lineno, cur.Offset)
			}
			cur.Name = val
		case "description":
			if cur == nil {
				return nil, fmt.Errorf("template: line %d: Description before any Offset", lineno)
			}
			cur.Description = val
		default:
			return nil, fmt.Errorf("template: line %d: unknown key %q", lineno, key)
		}
	}
	if err := flush(len(strings.Split(string(src), "\n"))); err != nil {
		return nil, err
	}
	if t.Name == "" {
		return nil, errors.New("template: missing Template name")
	}
	if len(t.Fields) == 0 {
		return nil, errors.New("template: no fields defined")
	}
	sort.SliceStable(t.Fields, func(i, j int) bool { return t.Fields[i].Offset < t.Fields[j].Offset })
	for _, f := range t.Fields {
		if end := f.Offset + f.Size; end > t.Size {
			t.Size = end
		}
	}
	return t, nil
}

// byteOrder returns the template's multi-byte order.
func (t *Template) byteOrder() binary.ByteOrder {
	if t.BigEndian {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// Apply reads the template's span from r at base and decodes every
// field. The whole span must be readable: a template that runs past the
// end of the data is an error, not a half-filled table.
func (t *Template) Apply(r io.ReaderAt, base int64) ([]Value, error) {
	if base < 0 {
		return nil, errors.New("template: negative base offset")
	}
	if t.Size == 0 {
		return nil, errors.New("template: empty template")
	}
	buf := make([]byte, t.Size)
	n, err := r.ReadAt(buf, base)
	if int64(n) < t.Size {
		return nil, fmt.Errorf("template %q needs %d bytes at 0x%x, only %d readable",
			t.Name, t.Size, base, n)
	}
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("template %q: read: %w", t.Name, err)
	}
	bo := t.byteOrder()
	out := make([]Value, 0, len(t.Fields))
	for _, f := range t.Fields {
		raw := buf[f.Offset : f.Offset+f.Size]
		out = append(out, Value{
			Name:    f.Name,
			Offset:  base + f.Offset,
			Type:    string(f.Type),
			Display: format(f, raw, bo),
			Raw:     append([]byte(nil), raw...),
		})
	}
	return out, nil
}

// format renders one field's bytes for display.
func format(f Field, raw []byte, bo binary.ByteOrder) string {
	// For byte-buffers Count is the length, not an array: a string[8] is
	// one 8-byte string, not eight 1-byte strings.
	if f.Type == TypeString || f.Type == TypeChar || f.Type == TypeBytes {
		return formatOne(f.Type, raw, bo)
	}
	one := func(b []byte) string {
		return formatOne(f.Type, b, bo)
	}
	if f.Count == 1 {
		return one(raw)
	}
	parts := make([]string, 0, f.Count)
	us := int(f.Size / int64(f.Count))
	for i := 0; i < f.Count; i++ {
		parts = append(parts, one(raw[i*us:(i+1)*us]))
	}
	return strings.Join(parts, "  ")
}

func formatOne(t FieldType, b []byte, bo binary.ByteOrder) string {
	switch t {
	case TypeU8:
		return fmt.Sprintf("0x%02x (%d)", b[0], b[0])
	case TypeU16:
		v := bo.Uint16(b)
		return fmt.Sprintf("0x%04x (%d)", v, v)
	case TypeU32:
		v := bo.Uint32(b)
		return fmt.Sprintf("0x%08x (%d)", v, v)
	case TypeU64:
		v := bo.Uint64(b)
		return fmt.Sprintf("0x%016x (%d)", v, v)
	case TypeI8:
		return fmt.Sprintf("%d", int8(b[0]))
	case TypeI16:
		return fmt.Sprintf("%d", int16(bo.Uint16(b)))
	case TypeI32:
		return fmt.Sprintf("%d", int32(bo.Uint32(b)))
	case TypeI64:
		return fmt.Sprintf("%d", int64(bo.Uint64(b)))
	case TypeF32:
		return strconv.FormatFloat(float64(math.Float32frombits(bo.Uint32(b))), 'g', -1, 32)
	case TypeF64:
		return strconv.FormatFloat(math.Float64frombits(bo.Uint64(b)), 'g', -1, 64)
	case TypeBytes:
		return strings.ToUpper(hex.EncodeToString(b))
	case TypeString, TypeChar:
		return strconv.Quote(strings.TrimRight(string(b), "\x00"))
	case TypeGUID:
		// The Microsoft GUID layout is mixed-endian (three little-endian
		// integers + 8 raw bytes) regardless of the template's byte order.
		return fmt.Sprintf("{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
			binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]),
			binary.LittleEndian.Uint16(b[6:8]),
			b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
	case TypeFiletime:
		ft := bo.Uint64(b)
		if ft == 0 {
			return "0 (unset)"
		}
		// FILETIME counts 100ns intervals since 1601-01-01 UTC. Convert
		// through Unix seconds so values beyond time.Duration's ~292-year
		// span still format, and refuse anything past year 9999 rather
		// than wrap.
		const ftPerSec = 10_000_000
		const maxSec = 265046774399 // seconds from 1601-01-01 to 9999-12-31
		if ft > maxSec*ftPerSec {
			return fmt.Sprintf("0x%016x (out of range)", ft)
		}
		sec := int64(ft/ftPerSec) - 11644473600
		nsec := int64(ft%ftPerSec) * 100
		ts := time.Unix(sec, nsec).UTC()
		return ts.Format(time.RFC3339Nano) + fmt.Sprintf(" (0x%x)", ft)
	case TypeUnixTime:
		v := bo.Uint32(b)
		if v == 0 {
			return "0 (unset)"
		}
		return time.Unix(int64(v), 0).UTC().Format(time.RFC3339) + fmt.Sprintf(" (%d)", v)
	case TypeBool8:
		return boolStr(b[0] != 0)
	case TypeBool16:
		return boolStr(bo.Uint16(b) != 0)
	case TypeBool32:
		return boolStr(bo.Uint32(b) != 0)
	}
	return hex.EncodeToString(b)
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
