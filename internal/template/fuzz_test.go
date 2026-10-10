package template

import (
	"bytes"
	"testing"
)

// validTemplate is a small well-formed template used as the primary seed.
const validTemplate = `Template=DOS Header
Comment=First 16 bytes of a PE file

Offset=0
Type=u16
Name=e_magic

Offset=2
Type=u16[3]
Name=header

Offset=8
Type=guid
Name=id
`

// FuzzTemplateApply parses arbitrary template text and, when it compiles,
// applies it to arbitrary document bytes. Both stages must stay panic-free;
// template Size is capped before Apply so a fuzzed Offset cannot force an
// unbounded allocation.
func FuzzTemplateApply(f *testing.F) {
	f.Add(validTemplate, []byte("MZ\x90\x00hello world, this is data!"))
	f.Add(validTemplate, []byte{})
	f.Add("Template=x\nOffset=0\nType=u32\nName=a\n", []byte{1, 2, 3, 4})
	f.Add("Offset=0\nType=nope\nName=a\n", []byte{1})           // unknown type
	f.Add("Template=x\nOffset=-4\nType=u8\nName=a\n", []byte{}) // bad offset
	f.Add("just some prose\n", []byte{})                        // not key=value
	f.Add("", []byte{})                                         // empty
	f.Add("Template=x\n", []byte{})                             // no fields
	f.Fuzz(func(t *testing.T, src string, data []byte) {
		if len(src) > 64<<10 || len(data) > 1<<20 {
			t.Skip("input too large")
		}
		tpl, err := Parse([]byte(src))
		if err != nil {
			return
		}
		if tpl.Size > 1<<20 {
			t.Skip("template span too large to apply")
		}
		_, _ = tpl.Apply(bytes.NewReader(data), 0)
		_, _ = tpl.Apply(bytes.NewReader(data), int64(len(data))/2)
	})
}
