package fs

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// record builds a minimal in-memory MFT record with the given attrs.
func record(num uint64, flags uint16, attrs ...ntfsAttr) *ntfsRecord {
	return &ntfsRecord{num: num, flags: flags, attrs: attrs}
}

// residentDataAttr builds a resident named $DATA attribute.
func residentDataAttr(name string, content []byte) ntfsAttr {
	return ntfsAttr{typ: ntfsAttrData, resident: true, name: name, content: content, realSize: int64(len(content))}
}

func TestStreamsOf(t *testing.T) {
	r := record(24, ntfsRecInUse,
		ntfsAttr{typ: ntfsAttrStdInfo, resident: true},
		ntfsAttr{typ: ntfsAttrFileName, resident: true, name: "$FILE_NAME"},
		// Unnamed default stream — must NOT be listed (it is the file).
		residentDataAttr("", []byte("file body")),
		// Named streams — the ADS we want.
		residentDataAttr("secret", []byte("hidden!")),
		ntfsAttr{typ: ntfsAttrData, name: "big", realSize: 1 << 20},
		// System internal stream — skipped by the "$" filter.
		residentDataAttr("$Secure", []byte("x")),
	)
	got := streamsOf(r, "report.pdf")
	if len(got) != 2 {
		t.Fatalf("len=%d got=%+v", len(got), got)
	}
	if got[0].Name != "secret" || got[0].Path != "report.pdf:secret" || got[0].Size != 7 || !got[0].Resident {
		t.Errorf("stream0=%+v", got[0])
	}
	if got[1].Name != "big" || got[1].Size != 1<<20 || got[1].Resident {
		t.Errorf("stream1=%+v", got[1])
	}
}

func TestStreamsOfFlags(t *testing.T) {
	r := record(25, ntfsRecInUse,
		residentDataAttr("", []byte("body")),
		ntfsAttr{typ: ntfsAttrData, name: "zipped", flags: ntfsAttrCompressed, realSize: 99},
		ntfsAttr{typ: ntfsAttrData, name: "locked", flags: ntfsAttrEncrypted, realSize: 5},
	)
	got := streamsOf(r, "f")
	if len(got) != 2 || !got[0].Compressed || !got[1].Encrypted {
		t.Fatalf("got=%+v", got)
	}
}

func TestStreamsOfEmpty(t *testing.T) {
	r := record(26, ntfsRecInUse, residentDataAttr("", []byte("body")))
	if got := streamsOf(r, "f"); len(got) != 0 {
		t.Fatalf("got=%+v", got)
	}
}

func TestReadStreamAttrResident(t *testing.T) {
	n := &ntfsFS{}
	a := residentDataAttr("s", []byte("stream-data"))
	buf := make([]byte, 6)
	got, err := readStreamAttr(n, &a, 7, buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if got != 4 || string(buf[:got]) != "data" {
		t.Fatalf("got=%d %q", got, buf[:got])
	}
	// Offset past end → EOF, zero bytes.
	if _, err := readStreamAttr(n, &a, 100, buf); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF got %v", err)
	}
	// Negative offset rejected.
	if _, err := readStreamAttr(n, &a, -1, buf); err == nil {
		t.Error("negative offset accepted")
	}
}

func TestReadStreamAttrCompressedRejected(t *testing.T) {
	n := &ntfsFS{}
	a := ntfsAttr{typ: ntfsAttrData, name: "c", flags: ntfsAttrCompressed, realSize: 10}
	if _, err := readStreamAttr(n, &a, 0, make([]byte, 4)); err == nil {
		t.Error("compressed stream read accepted")
	}
	a.flags = ntfsAttrEncrypted
	if _, err := readStreamAttr(n, &a, 0, make([]byte, 4)); err == nil {
		t.Error("encrypted stream read accepted")
	}
}

// nonADSFS is a stub FS without the ADS capability.
type nonADSFS struct{}

func (nonADSFS) Type() string                 { return "fat32" }
func (nonADSFS) Label() string                { return "" }
func (nonADSFS) TotalSize() int64             { return 0 }
func (nonADSFS) List(string) ([]Entry, error) { return nil, nil }
func (nonADSFS) Stat(string) (Entry, error)   { return Entry{}, nil }
func (nonADSFS) ReadAt(string, int64, []byte) (int, error) {
	return 0, io.EOF
}

func TestADSStreamsCapabilityProbe(t *testing.T) {
	streams, ok, err := ADSStreams(nonADSFS{}, "/x")
	if ok || err != nil || streams != nil {
		t.Fatalf("streams=%v ok=%v err=%v", streams, ok, err)
	}
	if _, err := ADSReadAt(nonADSFS{}, "/x", "s", 0, make([]byte, 1)); err == nil {
		t.Error("ADSReadAt on non-ADS fs accepted")
	}
}

func TestReadStreamAttrFullAndShort(t *testing.T) {
	n := &ntfsFS{}
	data := []byte("0123456789")
	a := residentDataAttr("s", data)
	buf := make([]byte, len(data))
	got, err := readStreamAttr(n, &a, 0, buf)
	if err != nil || got != len(data) || !bytes.Equal(buf, data) {
		t.Fatalf("got=%d err=%v buf=%q", got, err, buf)
	}
	// Short read at tail yields io.EOF with the remaining bytes.
	tail := make([]byte, 8)
	got, err = readStreamAttr(n, &a, 7, tail)
	if !errors.Is(err, io.EOF) || got != 3 || string(tail[:got]) != "789" {
		t.Fatalf("got=%d err=%v tail=%q", got, err, tail[:got])
	}
}
