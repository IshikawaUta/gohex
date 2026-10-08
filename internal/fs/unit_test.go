package fs

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// --- rangeReader -----------------------------------------------------------

func TestRangeReaderUnit(t *testing.T) {
	src := memReader{b: []byte("0123456789")}
	r := rangeReader{src: src, off: 2, size: 5} // exposes "23456"
	if r.Size() != 5 {
		t.Fatalf("Size=%d", r.Size())
	}
	buf := make([]byte, 3)
	if n, err := r.ReadAt(buf, 0); n != 3 || err != nil || string(buf) != "234" {
		t.Fatalf("ReadAt: n=%d err=%v buf=%q", n, err, buf)
	}
	// Short read inside the range → io.EOF.
	buf = make([]byte, 3)
	if n, err := r.ReadAt(buf, 3); n != 2 || !errors.Is(err, io.EOF) || string(buf[:2]) != "56" {
		t.Fatalf("partial: n=%d err=%v buf=%q", n, err, buf)
	}
	if _, err := r.ReadAt(buf, -1); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("negative off: %v", err)
	}
	if _, err := r.ReadAt(buf, 5); !errors.Is(err, io.EOF) {
		t.Fatalf("off==size: %v", err)
	}
	if _, err := r.ReadAt(buf, 99); !errors.Is(err, io.EOF) {
		t.Fatalf("off>size: %v", err)
	}
	// readFull fails on a short range.
	if err := r.readFull(make([]byte, 4), 4); !errors.Is(err, io.EOF) {
		t.Fatalf("readFull: %v", err)
	}
	if err := r.readFull(make([]byte, 2), 0); err != nil {
		t.Fatalf("readFull ok: %v", err)
	}
}

// failingReader always errors on read (used for Probe boot-area failures).
type failingReader struct{}

func (failingReader) Size() int64 { return 1 << 20 }
func (failingReader) ReadAt(p []byte, off int64) (int, error) {
	return 0, errors.New("boom")
}

// --- Probe edges -----------------------------------------------------------

func TestProbeEdgeErrors(t *testing.T) {
	img := make([]byte, 8192)
	if _, err := Probe(memReader{img}, -1, 0); err == nil {
		t.Fatal("negative offset accepted")
	}
	if _, err := Probe(memReader{img}, 9000, 0); err == nil {
		t.Fatal("offset beyond size accepted")
	}
	if _, err := Probe(memReader{img}, 0, 100); err == nil || !strings.Contains(err.Error(), "range too small") {
		t.Fatalf("small range: %v", err)
	}
	if _, err := Probe(memReader{img}, 4096, 999999); err == nil {
		t.Fatal("clamped-to-end garbage accepted")
	}
	if _, err := Probe(memReader{img}, 0, -1); err == nil {
		t.Fatal("negative length garbage accepted")
	}
	if _, err := Probe(failingReader{}, 0, 0); err == nil || !strings.Contains(err.Error(), "boot area") {
		t.Fatalf("boot read failure: %v", err)
	}
}

// --- probeApple ------------------------------------------------------------

func TestProbeAppleMessages(t *testing.T) {
	cases := []struct {
		name  string
		setup func([]byte)
		want  string
	}{
		{"hfsplus", func(b []byte) { b[1024], b[1025] = 'H', '+' }, "hfs+:"},
		{"hfsplusHX", func(b []byte) { b[1024], b[1025] = 'H', 'X' }, "hfs+:"},
		{"hfs", func(b []byte) { b[1024], b[1025] = 'B', 'D' }, "HFS detected"},
		{"apfs", func(b []byte) { copy(b[32:], "NXSB") }, "apfs:"},
		{"unknown", nil, "unrecognized"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			img := make([]byte, 8192)
			if tc.setup != nil {
				tc.setup(img)
			}
			_, err := Probe(memReader{img}, 0, int64(len(img)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

// --- SUSP / Rock Ridge -----------------------------------------------------

func suspNM(name string) []byte {
	e := make([]byte, 5+len(name))
	e[0], e[1] = 'N', 'M'
	e[2] = byte(len(e))
	e[3] = 1 // CONTINUE flag
	copy(e[5:], name)
	return e
}

func TestRRNameUnit(t *testing.T) {
	sp := []byte{'S', 'P', 7, 0xEE, 0x01, 0x01, 0x00}
	// SP marker followed by NM.
	sys := append(append([]byte{}, sp...), suspNM("readme.txt")...)
	if got := rrName(sys); got != "readme.txt" {
		t.Fatalf("with SP: %q", got)
	}
	// No SP marker: NM first (root entries other than ".").
	if got := rrName(suspNM("plain")); got != "plain" {
		t.Fatalf("no SP: %q", got)
	}
	// ST terminator before NM.
	sys = append(append([]byte{}, sp...), 'S', 'T', 4, 0)
	if got := rrName(sys); got != "" {
		t.Fatalf("ST: %q", got)
	}
	// Invalid (too short) entry length.
	if got := rrName([]byte{'X', 'Y', 2, 0}); got != "" {
		t.Fatalf("short elen: %q", got)
	}
	// Entry length overruns the buffer.
	if got := rrName([]byte{'A', 'B', 'C', 'D', 'E', 'F', 'G'}); got != "" {
		t.Fatalf("overrun elen: %q", got)
	}
	// NM entry with no name payload.
	if got := rrName([]byte{'N', 'M', 5, 1, 0}); got != "" {
		t.Fatalf("empty NM: %q", got)
	}
	// Unknown signature, advances and ends.
	if got := rrName([]byte{'P', 'X', 4, 0}); got != "" {
		t.Fatalf("unknown sig: %q", got)
	}
	// Too short to hold any entry.
	if got := rrName([]byte{1, 2, 3}); got != "" {
		t.Fatalf("tiny: %q", got)
	}
}

// --- helpers / attribute name tables ---------------------------------------

func TestLeOOB(t *testing.T) {
	if le16([]byte{1}, 0) != 0 || le32([]byte{1}, 0) != 0 || le64([]byte{1}, 0) != 0 {
		t.Fatal("OOB reads must return 0")
	}
	if le16([]byte{0x34, 0x12}, 0) != 0x1234 {
		t.Fatal("le16 value")
	}
	if le32([]byte{1, 2, 3, 4}, 0) != 0x04030201 {
		t.Fatal("le32 value")
	}
	if le64([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 0) != 0x0807060504030201 {
		t.Fatal("le64 value")
	}
}

func TestExtTypeAttrUnit(t *testing.T) {
	cases := map[uint16]string{
		extModeSymlink: "symlink",
		0xC000:         "socket",
		0x1000:         "fifo",
		0x2000:         "chardev",
		0x6000:         "blockdev",
		extModeDir:     "",
		extModeReg:     "",
	}
	for mode, want := range cases {
		got := extTypeAttr(mode)
		if want == "" {
			if len(got) != 0 {
				t.Fatalf("mode %#o: %v", mode, got)
			}
			continue
		}
		if len(got) != 1 || got[0] != want {
			t.Fatalf("mode %#o: %v, want %q", mode, got, want)
		}
	}
	// The type mask must be applied (not the raw mode).
	if len(extTypeAttr(extModeSymlink|0x777)) != 1 {
		t.Fatal("mask not applied")
	}
}

func TestAttrNameTables(t *testing.T) {
	if got := fatAttrNames(fatAttrRO | fatAttrHidden | fatAttrSystem | fatAttrArc); len(got) != 4 {
		t.Fatalf("fatAttrNames: %v", got)
	}
	if got := fatAttrNames(0); len(got) != 0 {
		t.Fatalf("fatAttrNames none: %v", got)
	}
	if got := exfatAttrNames(0x0007); len(got) != 3 {
		t.Fatalf("exfatAttrNames: %v", got)
	}
	if got := exfatAttrNames(0); len(got) != 0 {
		t.Fatalf("exfatAttrNames none: %v", got)
	}
}

func TestTimesZero(t *testing.T) {
	if !extTime(0).IsZero() {
		t.Fatal("extTime(0) must be zero")
	}
	if extTime(1700000000).Unix() != 1700000000 {
		t.Fatal("extTime value")
	}
	if !ntfsTime(0).IsZero() || !ntfsTime(0xFFFFFFFFFFFFFFFF).IsZero() {
		t.Fatal("ntfsTime sentinels must be zero")
	}
	// A value before the epoch offset is rejected as zero.
	if !ntfsTime(1).IsZero() {
		t.Fatal("ntfsTime pre-1601 must be zero")
	}
	if ntfsTime(116444736000000000+2e9).Year() != 1970 {
		t.Fatal("ntfsTime epoch conversion")
	}
}

func TestFatShortNameForms(t *testing.T) {
	e := make([]byte, 32)
	copy(e, "TEST    TXT")
	if got := fatShortName(e); got != "TEST.TXT" {
		t.Fatalf("plain: %q", got)
	}
	e[0] = 0xE5 // deleted: leading char lost per spec
	if got := fatShortName(e); got != "?EST.TXT" {
		t.Fatalf("deleted: %q", got)
	}
	e[0] = 0x05 // real 0xE5 encoded as 0x05
	if got := fatShortName(e); got != "\xE5EST.TXT" {
		t.Fatalf("encoded: %q", got)
	}
	e[0] = ' '
	e[1], e[2], e[3] = ' ', ' ', ' '
	if got := fatShortName(e); got != "" {
		t.Fatalf("empty base: %q", got)
	}
	// base with dot preserved in ext only.
	copy(e, "FOO     BAR")
	if got := fatShortName(e); got != "FOO.BAR" {
		t.Fatalf("with ext: %q", got)
	}
}
