package hash

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

// vectors: input → expected hex digests, computed independently (Python
// zlib/hashlib and published CRC check values).
func vectors(t *testing.T) []struct {
	in   string
	want map[Algo]string
} {
	t.Helper()
	return []struct {
		in   string
		want map[Algo]string
	}{
		{
			in: "123456789",
			want: map[Algo]string{
				CRC16:      "29b1",
				CRC16IBM:   "bb3d",
				CRC32:      "cbf43926",
				CRC32C:     "e3069283",
				CRC64:      "995dc9bbdf1939fa",
				Adler32:    "091e01de",
				MD5:        "25f9e794323b453885f5181f1b624d0b",
				SHA1:       "f7c3bc1d808e04732adf679965ccc34ca7ae3441",
				SHA256:     "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225",
				BLAKE2b256: "16e0bf1f85594a11e75030981c0b670370b3ad83a43f49ae58a2fd6f6513cde9",
			},
		},
		{
			in: "abc",
			want: map[Algo]string{
				CRC16:      "514a",
				CRC16IBM:   "9738",
				CRC32:      "352441c2",
				CRC32C:     "364b3fb7",
				CRC64:      "2cd8094a1a277627",
				Adler32:    "024d0127",
				MD5:        "900150983cd24fb0d6963f7d28e17f72",
				SHA1:       "a9993e364706816aba3e25717850c26c9cd0d89d",
				SHA256:     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
				BLAKE2b256: "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
				BLAKE3:     "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
			},
		},
		{
			in: "",
			want: map[Algo]string{
				CRC16:      "ffff",
				CRC16IBM:   "0000",
				CRC32:      "00000000",
				CRC32C:     "00000000",
				CRC64:      "0000000000000000",
				Adler32:    "00000001",
				MD5:        "d41d8cd98f00b204e9800998ecf8427e",
				SHA1:       "da39a3ee5e6b4b0d3255bfef95601890afd80709",
				SHA256:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				BLAKE2b256: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
				XXH64:      "ef46db3751d8e999",
			},
		},
	}
}

func TestKnownVectors(t *testing.T) {
	for _, tc := range vectors(t) {
		for algo, want := range tc.want {
			got, err := Sum(algo, []byte(tc.in))
			if err != nil {
				t.Errorf("Sum(%s, %q): %v", algo, tc.in, err)
				continue
			}
			if fmt.Sprintf("%x", got) != want {
				t.Errorf("Sum(%s, %q) = %x, want %s", algo, tc.in, got, want)
			}
			if len(got) != algo.Size() {
				t.Errorf("Sum(%s) len=%d, want %d", algo, len(got), algo.Size())
			}
		}
	}
}

func TestSHA512Vectors(t *testing.T) {
	got, err := Sum(SHA512, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	want := "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
		"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
	if fmt.Sprintf("%x", got) != want {
		t.Errorf("SHA512(abc) = %x", got)
	}
}

func TestParseAlgo(t *testing.T) {
	cases := map[string]Algo{
		"sha256": SHA256, "SHA-256": SHA256, "Sha256": SHA256,
		"md5": MD5, "blake3": BLAKE3, "xxh64": XXH64, "crc32c": CRC32C,
		"blake2b": BLAKE2b256, "adler-32": Adler32, "sha-1": SHA1,
	}
	for in, want := range cases {
		got, err := Parse(in)
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := Parse("crc99"); err == nil {
		t.Error("unknown algo should fail")
	}
}

func TestAlgoProperties(t *testing.T) {
	for _, a := range All() {
		if a.Size() <= 0 {
			t.Errorf("%s size = %d", a, a.Size())
		}
		if _, err := New(a); err != nil {
			t.Errorf("New(%s): %v", a, err)
		}
	}
	for _, a := range []Algo{SHA256, SHA512, BLAKE2b256, BLAKE3} {
		if !a.Cryptographic() {
			t.Errorf("%s should be cryptographic", a)
		}
	}
	for _, a := range []Algo{MD5, SHA1, CRC32, XXH64} {
		if a.Cryptographic() {
			t.Errorf("%s should be legacy", a)
		}
	}
	if Algo("nope").Size() != 0 {
		t.Error("unknown size")
	}
	if _, err := New(Algo("nope")); err == nil {
		t.Error("unknown New should fail")
	}
	if _, err := Sum(Algo("nope"), nil); err == nil {
		t.Error("unknown Sum should fail")
	}
	if _, err := Reader(Algo("nope"), nil, nil); err == nil {
		t.Error("unknown Reader should fail")
	}
}

func TestReaderStreaming(t *testing.T) {
	// Streaming must equal one-shot for every algorithm.
	data := bytes.Repeat([]byte("gohex"), 10000) // 50 KB
	for _, a := range All() {
		one, err := Sum(a, data)
		if err != nil {
			t.Fatal(err)
		}
		stream, err := Reader(a, bytes.NewReader(data), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(one, stream) {
			t.Errorf("%s: one-shot %x != stream %x", a, one, stream)
		}
	}
}

func TestReaderProgressAndCancel(t *testing.T) {
	data := bytes.Repeat([]byte{0x5A}, 1<<20) // 1 MiB
	var calls int
	_, err := Reader(SHA256, bytes.NewReader(data), func(total int64) bool {
		calls++
		return true
	})
	if err != nil || calls == 0 {
		t.Fatalf("progress: calls=%d err=%v", calls, err)
	}
	_, err = Reader(SHA256, bytes.NewReader(data), func(total int64) bool {
		return false
	})
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("cancel: %v", err)
	}
}

func TestReaderReadError(t *testing.T) {
	_, err := Reader(SHA256, errReader{}, nil)
	if err == nil {
		t.Fatal("read error should propagate")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestFormat(t *testing.T) {
	if got := Format(SHA256, []byte{0xAB, 0xCD}, false); got != "abcd" {
		t.Errorf("plain = %q", got)
	}
	if got := Format(SHA256, []byte{0xAB, 0xCD}, true); got != "SHA-256: abcd" {
		t.Errorf("prefixed = %q", got)
	}
}
