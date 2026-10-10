package bincoding

import (
	"strings"
	"testing"
)

// FuzzDecode runs every supported text encoding over arbitrary bytes. Decode
// never fails by design, so the only requirement is no panic.
func FuzzDecode(f *testing.F) {
	f.Add(0, []byte("Hello, GoHex!"))
	f.Add(1, []byte("Hello, \xc3\xa9\xc3\xa8!"))   // UTF-8
	f.Add(2, []byte("A\x00B\x00\x00\xd8"))         // UTF-16 LE with a lone surrogate
	f.Add(3, []byte{0x00, 0x41, 0x00, 0xFF})       // UTF-16 BE
	f.Add(4, []byte{0xC8, 0x85, 0x96, 0x81, 0x99}) // EBCDIC CP037
	f.Add(2, []byte{0x41})                         // odd length
	f.Add(1, []byte{0xFF, 0xFE, 0x00})             // invalid UTF-8
	f.Fuzz(func(t *testing.T, enc int, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("input too large")
		}
		all := All()
		e := all[((enc%len(all))+len(all))%len(all)]
		_ = Decode(e, data)
		_ = ColumnText(e, data)
		_ = Encode(e, Decode(e, data))
	})
}

// FuzzDecodeIntelHex fuzzes the Intel HEX record parser over arbitrary text.
func FuzzDecodeIntelHex(f *testing.F) {
	f.Add([]byte(EncodeIntelHex([]byte("hello, world"), 0x1000)))
	f.Add([]byte(":100000000102030405060708090A0B0C0D0E0F00E8\r\n:00000001FF\r\n"))
	f.Add([]byte(":00000001FF"))   // no trailing newline
	f.Add([]byte(":10000000"))     // truncated record
	f.Add([]byte(":ZZ00000000\n")) // bad checksum digits
	f.Add([]byte("just prose\n"))  // no records at all
	f.Add([]byte{})                // empty
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("input too large")
		}
		_, _ = DecodeIntelHex(strings.NewReader(string(data)))
	})
}

// FuzzDecodeSRecords fuzzes the Motorola S-record parser over arbitrary text.
func FuzzDecodeSRecords(f *testing.F) {
	f.Add([]byte(EncodeSRecords([]byte("hello, world"), 0x1000)))
	f.Add([]byte("S1131000000102030405060708090A0B0C0D0E0F60\nS9031000EC\n"))
	f.Add([]byte("S9031000EC"))   // no trailing newline
	f.Add([]byte("S1"))           // truncated record
	f.Add([]byte("S7"))           // unsupported type
	f.Add([]byte("no records\n")) // garbage
	f.Add([]byte{})               // empty
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip("input too large")
		}
		_, _ = DecodeSRecords(strings.NewReader(string(data)))
	})
}
