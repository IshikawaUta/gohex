package template

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
	"testing"
)

func TestParseBasic(t *testing.T) {
	src := `
# a comment
Template=DOS Header
Comment=First 64 bytes of a PE file

Offset=0
Type=u16
Name=e_magic
Description=Magic number

Offset=2
Type=u16[3]
Name=e_cblp

Offset=8
Type=string[8]
Name=e_res
`
	tpl, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if tpl.Name != "DOS Header" || tpl.Comment != "First 64 bytes of a PE file" {
		t.Fatalf("meta = %q %q", tpl.Name, tpl.Comment)
	}
	if tpl.BigEndian {
		t.Error("BigEndian = true, want default little")
	}
	if len(tpl.Fields) != 3 {
		t.Fatalf("fields = %d", len(tpl.Fields))
	}
	f0, f1, f2 := tpl.Fields[0], tpl.Fields[1], tpl.Fields[2]
	if f0.Name != "e_magic" || f0.Type != TypeU16 || f0.Offset != 0 || f0.Size != 2 {
		t.Errorf("field0 = %+v", f0)
	}
	if f0.Description != "Magic number" {
		t.Errorf("field0 desc = %q", f0.Description)
	}
	if f1.Type != TypeU16 || f1.Count != 3 || f1.Size != 6 {
		t.Errorf("field1 = %+v", f1)
	}
	if f2.Type != TypeString || f2.Count != 8 || f2.Size != 8 {
		t.Errorf("field2 = %+v", f2)
	}
	if tpl.Size != 16 {
		t.Errorf("Size = %d, want 16", tpl.Size)
	}
}

func TestParseSortsByOffsetAndAliases(t *testing.T) {
	src := `
Template=Aliases
Endian=big

Offset=8
Type=dword
Name=late

Offset=0
Type=byte
Name=b

Offset=4
Type=Word
Name=w
Count=2
`
	tpl, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if !tpl.BigEndian {
		t.Error("BigEndian = false, want true")
	}
	if tpl.Fields[0].Name != "b" || tpl.Fields[0].Type != TypeU8 {
		t.Errorf("first field = %+v", tpl.Fields[0])
	}
	if tpl.Fields[1].Name != "w" || tpl.Fields[1].Count != 2 || tpl.Fields[1].Size != 4 {
		t.Errorf("second field = %+v", tpl.Fields[1])
	}
	if tpl.Fields[2].Name != "late" || tpl.Fields[2].Type != TypeU32 || tpl.Fields[2].Size != 4 {
		t.Errorf("third field = %+v", tpl.Fields[2])
	}
}

func TestParseErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want string
	}{
		{"missing name", "Offset=0\nType=u8\nName=x\n", "missing Template name"},
		{"no fields", "Template=T\n", "no fields"},
		{"bad line", "Template=T\nnot-a-kv\n", "want key=value"},
		{"unknown key", "Template=T\nOffset=0\nType=u8\nName=x\nFoo=1\n", "unknown key"},
		{"unknown type", "Template=T\nOffset=0\nType=widget\nName=x\n", "unknown field type"},
		{"type before offset", "Template=T\nType=u8\n", "Type before any Offset"},
		{"name before offset", "Template=T\nName=x\n", "Name before any Offset"},
		{"count before offset", "Template=T\nCount=2\n", "Count before any Offset"},
		{"description before offset", "Template=T\nDescription=x\n", "Description before any Offset"},
		{"field no name", "Template=T\nOffset=0\nType=u8\n", "has no Name"},
		{"bad offset", "Template=T\nOffset=-1\nType=u8\nName=x\n", "bad offset"},
		{"bad count", "Template=T\nOffset=0\nType=u8\nCount=0\nName=x\n", "bad Count"},
		{"dup type", "Template=T\nOffset=0\nType=u8\nType=u8\nName=x\n", "duplicate Type"},
		{"dup name", "Template=T\nOffset=0\nType=u8\nName=x\nName=y\n", "duplicate Name"},
		{"bad endian", "Template=T\nEndian=middle\n", "unknown endian"},
		{"bad array", "Template=T\nOffset=0\nType=u8[\nName=x\n", "malformed array"},
		{"bad array count", "Template=T\nOffset=0\nType=u8[0]\nName=x\n", "malformed array count"},
		{"empty template name", "Template=\n", "empty Template name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.src))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestApplyLittleEndianVectors(t *testing.T) {
	// u8, u16, u32, u64, i16, f32, bytes[4], string[6], bool8, unixtime
	src := `
Template=Vector

Offset=0
Type=u8
Name=b

Offset=1
Type=u16
Name=w

Offset=3
Type=u32
Name=d

Offset=7
Type=u64
Name=q

Offset=15
Type=i16
Name=si

Offset=17
Type=f32
Name=f

Offset=21
Type=bytes[4]
Name=raw

Offset=25
Type=string[6]
Name=s

Offset=31
Type=bool8
Name=flag

Offset=32
Type=unixtime
Name=ts
`
	tpl, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 36)
	data[0] = 0x1a
	binary.LittleEndian.PutUint16(data[1:3], 0x1234)
	binary.LittleEndian.PutUint32(data[3:7], 0xDEADBEEF)
	binary.LittleEndian.PutUint64(data[7:15], 0x0123456789ABCDEF)
	binary.LittleEndian.PutUint16(data[15:17], 0xFFFE) // -2
	binary.LittleEndian.PutUint32(data[17:21], math.Float32bits(1.5))
	copy(data[21:25], []byte{0xDE, 0xAD, 0xBE, 0xEF})
	copy(data[25:31], "MZ\x00\x00\x00\x00")
	data[31] = 1
	binary.LittleEndian.PutUint32(data[32:36], 1700000000) // 2023-11-14T22:13:20Z

	vals, err := tpl.Apply(bytes.NewReader(data), 0)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Value{}
	for _, v := range vals {
		byName[v.Name] = v
	}
	checks := map[string]string{
		"b":    "0x1a (26)",
		"w":    "0x1234 (4660)",
		"d":    "0xdeadbeef (3735928559)",
		"q":    "0x0123456789abcdef (81985529216486895)",
		"si":   "-2",
		"f":    "1.5",
		"raw":  "DEADBEEF",
		"s":    "\"MZ\"",
		"flag": "true",
		"ts":   "2023-11-14T22:13:20Z (1700000000)",
	}
	for name, want := range checks {
		if got := byName[name].Display; got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if byName["b"].Offset != 0 || byName["ts"].Offset != 32 {
		t.Errorf("absolute offsets wrong: %+v", byName["b"])
	}
}

func TestApplyBaseOffsetAndEndian(t *testing.T) {
	src := `
Template=BE
Endian=big

Offset=0
Type=u32
Name=d

Offset=4
Type=guid
Name=id

Offset=20
Type=filetime
Name=ft
`
	tpl, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 0x100+28)
	binary.BigEndian.PutUint32(data[0x100:0x104], 0x11223344)
	copy(data[0x104:0x114], []byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00})
	// FILETIME for 2020-01-01T00:00:00Z = 132223104000000000
	binary.BigEndian.PutUint64(data[0x114:0x11c], 132223104000000000)

	vals, err := tpl.Apply(bytes.NewReader(data), 0x100)
	if err != nil {
		t.Fatal(err)
	}
	if vals[0].Display != "0x11223344 (287454020)" {
		t.Errorf("BE u32 = %q", vals[0].Display)
	}
	if vals[1].Display != "{00112233-6655-8877-99aa-bbccddeeff00}" {
		t.Errorf("guid = %q", vals[1].Display)
	}
	if !strings.HasPrefix(vals[2].Display, "2020-01-01T00:00:00Z") {
		t.Errorf("filetime = %q", vals[2].Display)
	}
	if vals[0].Offset != 0x100 || vals[2].Offset != 0x100+20 {
		t.Errorf("offsets = %d %d", vals[0].Offset, vals[2].Offset)
	}
}

func TestApplySpecialCases(t *testing.T) {
	src := `
Template=Special

Offset=0
Type=u32[3]
Name=arr

Offset=12
Type=filetime
Name=ft0

Offset=20
Type=unixtime
Name=ts0

Offset=24
Type=bool16
Name=b16

Offset=26
Type=f64
Name=d
`
	tpl, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 34)
	binary.LittleEndian.PutUint32(data[0:4], 1)
	binary.LittleEndian.PutUint32(data[4:8], 2)
	binary.LittleEndian.PutUint32(data[8:12], 3)
	// ft0 and ts0 stay zero → "unset"
	binary.LittleEndian.PutUint16(data[24:26], 0x0100)
	binary.LittleEndian.PutUint64(data[26:34], math.Float64bits(-2.25))

	vals, err := tpl.Apply(bytes.NewReader(data), 0)
	if err != nil {
		t.Fatal(err)
	}
	if vals[0].Display != "0x00000001 (1)  0x00000002 (2)  0x00000003 (3)" {
		t.Errorf("array = %q", vals[0].Display)
	}
	if vals[1].Display != "0 (unset)" || vals[2].Display != "0 (unset)" {
		t.Errorf("zero times = %q %q", vals[1].Display, vals[2].Display)
	}
	if vals[3].Display != "true" {
		t.Errorf("bool16 = %q", vals[3].Display)
	}
	if vals[4].Display != "-2.25" {
		t.Errorf("f64 = %q", vals[4].Display)
	}
}

func TestApplyErrors(t *testing.T) {
	tpl, err := Parse([]byte("Template=T\nOffset=0\nType=u32\nName=x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tpl.Apply(bytes.NewReader(make([]byte, 2)), 0); err == nil || !strings.Contains(err.Error(), "only 2 readable") {
		t.Errorf("truncated: err = %v", err)
	}
	if _, err := tpl.Apply(bytes.NewReader(make([]byte, 8)), -1); err == nil {
		t.Error("negative base: err = nil")
	}
	empty := &Template{Name: "E"}
	if _, err := empty.Apply(bytes.NewReader(nil), 0); err == nil {
		t.Error("empty template: err = nil")
	}
	// A full read at a non-zero base works when the data is large enough.
	vals, err := tpl.Apply(bytes.NewReader(make([]byte, 16)), 4)
	if err != nil {
		t.Fatal(err)
	}
	if vals[0].Offset != 4 {
		t.Errorf("offset = %d", vals[0].Offset)
	}
}

func TestFormatFiletimeOutOfRange(t *testing.T) {
	tpl, err := Parse([]byte("Template=T\nOffset=0\nType=filetime\nName=ft\n"))
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, math.MaxUint64)
	vals, err := tpl.Apply(bytes.NewReader(data), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(vals[0].Display, "out of range") {
		t.Errorf("display = %q, want out of range", vals[0].Display)
	}
}

func TestParseCRLFAndSemicolon(t *testing.T) {
	src := "Template=T\r\n; note\r\nOffset=0\r\nType=u8\r\nName=x\r\n"
	tpl, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if tpl.Fields[0].Name != "x" {
		t.Errorf("field = %+v", tpl.Fields[0])
	}
}
