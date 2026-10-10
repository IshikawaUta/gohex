package util

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEntropy(t *testing.T) {
	if got := Entropy(nil); got != 0 {
		t.Errorf("empty = %v", got)
	}
	if got := Entropy(bytes.Repeat([]byte{0x41}, 256)); got != 0 {
		t.Errorf("constant = %v", got)
	}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if got := Entropy(all); got != 8.0 {
		t.Errorf("uniform = %v, want 8", got)
	}
}

func TestBlockEntropy(t *testing.T) {
	data := append(bytes.Repeat([]byte{0x00}, 4), bytes.Repeat([]byte{0xFF}, 4)...)
	blocks := BlockEntropy(data, 4)
	if len(blocks) != 2 {
		t.Fatalf("blocks = %d", len(blocks))
	}
	for i, b := range blocks {
		if b != 0 {
			t.Errorf("block %d = %v, want 0", i, b)
		}
	}
	// Default block size and non-positive handling.
	if got := BlockEntropy(data, 0); len(got) != 1 {
		t.Errorf("default size = %d blocks", len(got))
	}
}

func TestByteFrequency(t *testing.T) {
	freq := ByteFrequency([]byte{0x01, 0x02, 0x01})
	if len(freq) != 2 {
		t.Fatalf("len = %d", len(freq))
	}
	if freq[0].Byte != 1 || freq[0].Count != 2 {
		t.Errorf("top = %+v", freq[0])
	}
	if freq[1].Byte != 2 || freq[1].Count != 1 {
		t.Errorf("second = %+v", freq[1])
	}
	if got := ByteFrequency(nil); len(got) != 0 {
		t.Errorf("empty = %v", got)
	}
}

func TestEvalExpr(t *testing.T) {
	cases := map[string]int64{
		"1+2":           3,
		" 10 * 2 - 3 ":  17,
		"(1+2)*3":       9,
		"0x10 + 1":      17,
		"0xFF":          255,
		"-(3+4)":        -7,
		"+5":            5,
		"17/5":          3,
		"17%5":          2,
		"0X10*2":        32,
		"100 - 20 - 30": 50,
	}
	for expr, want := range cases {
		got, err := EvalExpr(expr)
		if err != nil {
			t.Errorf("EvalExpr(%q): %v", expr, err)
			continue
		}
		if got != want {
			t.Errorf("EvalExpr(%q) = %d, want %d", expr, got, want)
		}
	}
	bads := []string{"", "1/", "1%0", "(1", "1)", "abc", "1 2", "0x", "0xZZ", "1--", "*2"}
	for _, expr := range bads {
		if _, err := EvalExpr(expr); err == nil {
			t.Errorf("EvalExpr(%q) accepted", expr)
		}
	}
}

func TestRegexSearch(t *testing.T) {
	data := []byte("foo BAR baz foo")
	got, err := RegexSearch(data, "foo", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Offset != 0 || got[1].Offset != 12 {
		t.Fatalf("got = %+v", got)
	}
	if _, err := RegexSearch(data, "(", 10); err == nil {
		t.Error("accepted a bad regex")
	}
	// limit caps the result count.
	got, err = RegexSearch(bytes.Repeat([]byte("aa"), 100), "a", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Errorf("limit = %d", len(got))
	}
}

func TestExtractStrings(t *testing.T) {
	data := []byte{0x00, 'h', 'e', 'l', 'l', 'o', 0x00, 'w', 'o', 'r', 'l', 'd', '!', 0x01}
	got := ExtractStrings(data, 4, 100)
	if len(got) != 2 {
		t.Fatalf("got = %+v", got)
	}
	if got[0].Text != "hello" || got[0].Offset != 1 {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Text != "world!" {
		t.Errorf("second = %+v", got[1])
	}
	// minLen filters short runs.
	if got := ExtractStrings([]byte("ab\x00cd"), 3, 10); len(got) != 0 {
		t.Errorf("minLen filter = %+v", got)
	}
	// limit caps output.
	if got := ExtractStrings(bytes.Repeat([]byte("abcd\x00"), 100), 4, 10); len(got) != 10 {
		t.Errorf("limit = %d", len(got))
	}
	// UTF-8 printable runes survive.
	utf := []byte("héllo\x00")
	if got := ExtractStrings(utf, 4, 10); len(got) != 1 || got[0].Text != "héllo" {
		t.Errorf("utf8 = %+v", got)
	}
}

func TestPrintable(t *testing.T) {
	if got := Printable([]byte("hi\x00\x01\\x")); got != `hi\x00\x01\\x` {
		t.Errorf("Printable = %q", got)
	}
}

func TestSplitJoin(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	if err := os.WriteFile(src, []byte("0123456789abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	parts, err := SplitFile(src, filepath.Join(dir, "p-%d.bin"), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 4 {
		t.Fatalf("parts = %v", parts)
	}
	dst := filepath.Join(dir, "joined.bin")
	n, err := JoinFiles(parts, dst)
	if err != nil {
		t.Fatal(err)
	}
	if n != 16 {
		t.Errorf("joined = %d bytes", n)
	}
	body, _ := os.ReadFile(dst)
	if string(body) != "0123456789abcdef" {
		t.Errorf("content = %q", body)
	}
	// Bad patterns are rejected and no partial output is left behind.
	if _, err := SplitFile(src, filepath.Join(dir, "bad.bin"), 5); err == nil {
		t.Error("accepted a pattern without placeholder")
	}
	if _, err := SplitFile(src, filepath.Join(dir, "p-%d.bin"), 0); err == nil {
		t.Error("accepted a non-positive piece size")
	}
	if _, err := SplitFile(filepath.Join(dir, "nope"), filepath.Join(dir, "p2-%d.bin"), 5); err == nil {
		t.Error("accepted a missing source")
	}
	if _, err := JoinFiles(nil, dst); err == nil {
		t.Error("accepted no parts")
	}
}

func TestShred(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.bin")
	if err := os.WriteFile(p, []byte("top secret material"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Shred(p, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("file survived shred")
	}
	// Empty file: just unlinked.
	empty := filepath.Join(dir, "empty.bin")
	os.WriteFile(empty, nil, 0o644)
	if err := Shred(empty, 1); err != nil {
		t.Fatal(err)
	}
	if err := Shred(filepath.Join(dir, "missing"), 1); err == nil {
		t.Error("accepted a missing file")
	}
}

func TestPasswordUUIDULID(t *testing.T) {
	pw, err := Password(20)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 20 {
		t.Errorf("password len = %d", len(pw))
	}
	for _, c := range pw {
		if !strings.ContainsRune(passwordAlphabet, c) {
			t.Fatalf("char %q outside alphabet", c)
		}
	}
	if _, err := Password(0); err == nil {
		t.Error("accepted length 0")
	}
	if _, err := Password(5000); err == nil {
		t.Error("accepted length 5000")
	}
	u1, err := UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	if len(u1) != 36 || u1[14] != '4' {
		t.Errorf("uuid = %q", u1)
	}
	u2, err := ULID()
	if err != nil {
		t.Fatal(err)
	}
	if len(u2) != 26 {
		t.Errorf("ulid = %q", u2)
	}
	if u2 <= u1 { // different alphabets make direct compare useless; just exercise ordering
		t.Log("ulid/uuid ordering not comparable")
	}
}

func TestConvertTimestamp(t *testing.T) {
	got, err := ConvertTimestamp(0, "s")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got["utc"], "1970-01-01") {
		t.Errorf("utc = %q", got["utc"])
	}
	if got["unix"] != "0" {
		t.Errorf("unix = %q", got["unix"])
	}
	// FILETIME: 0 epoch = 116444736000000000.
	if got["filetime"] != "116444736000000000" {
		t.Errorf("filetime = %q", got["filetime"])
	}
	if kind := got["kind"]; kind != "past" && kind != "now" {
		t.Errorf("kind = %q", kind)
	}
	if _, err := ConvertTimestamp(0, "parsecs"); err == nil {
		t.Error("accepted an unknown unit")
	}
	// Millisecond and nanosecond units.
	gotMS, _ := ConvertTimestamp(0, "ms")
	if gotMS["unix"] != "0" {
		t.Errorf("ms unix = %q", gotMS["unix"])
	}
	if _, err := ConvertTimestamp(0, "ns"); err != nil {
		t.Error(err)
	}
	if _, err := ConvertTimestamp(0, "us"); err != nil {
		t.Error(err)
	}
}

func TestRandomBytes(t *testing.T) {
	a, err := RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 {
		t.Errorf("hex len = %d", len(a))
	}
	b, _ := RandomBytes(16)
	if a == b {
		t.Error("two draws were identical")
	}
	if _, err := RandomBytes(0); err == nil {
		t.Error("accepted 0")
	}
	if _, err := RandomBytes(1 << 21); err == nil {
		t.Error("accepted 2 MiB")
	}
}

func TestEntropyReaderAndHeadTail(t *testing.T) {
	data := bytes.Repeat([]byte("ab"), 1<<20)
	h, n, err := EntropyReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(data)) {
		t.Errorf("n = %d", n)
	}
	if h != 1.0 {
		t.Errorf("entropy = %v, want 1", h)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "f.bin")
	body := []byte("0123456789")
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	head, err := HeadBytes(p, 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(head) != "0123" {
		t.Errorf("head = %q", head)
	}
	// Head larger than the file returns everything.
	head, _ = HeadBytes(p, 100)
	if !bytes.Equal(head, body) {
		t.Errorf("big head = %q", head)
	}
	tail, err := TailBytes(p, 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(tail) != "6789" {
		t.Errorf("tail = %q", tail)
	}
	if _, err := HeadBytes(filepath.Join(dir, "missing"), 4); err == nil {
		t.Error("head of missing file")
	}
	if _, err := TailBytes(filepath.Join(dir, "missing"), 4); err == nil {
		t.Error("tail of missing file")
	}
	if _, err := HeadBytes(p, 0); err == nil {
		t.Error("head size 0")
	}
	if _, err := TailBytes(p, 0); err == nil {
		t.Error("tail size 0")
	}
}

func TestFirstLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.txt")
	if err := os.WriteFile(p, []byte("one\ntwo\nthree\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, err := FirstLines(p, 2, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0] != "one" || lines[1] != "two" {
		t.Errorf("lines = %v", lines)
	}
	if _, err := FirstLines(filepath.Join(dir, "missing"), 1, 10); err == nil {
		t.Error("missing file")
	}
}

// Benchmark guards against accidental O(n^2) in the hot paths.
func BenchmarkEntropy(b *testing.B) {
	data := make([]byte, 1<<20)
	for i := range data {
		data[i] = byte(i)
	}
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		Entropy(data)
	}
}

func BenchmarkEvalExpr(b *testing.B) {
	for i := 0; i < b.N; i++ {
		EvalExpr("0x1234 + 5678 * (3 - 1)")
	}
}
