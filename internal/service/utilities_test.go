package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEntropyAndFreq(t *testing.T) {
	app := newTestApp(t)
	p := filepath.Join(t.TempDir(), "d.bin")
	if err := os.WriteFile(p, make([]byte, 1024), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := app.EntropyOf(p)
	if err != nil {
		t.Fatal(err)
	}
	if got["entropy"] != 0 {
		t.Errorf("zeros entropy = %v", got["entropy"])
	}
	if got["bytes"] != 1024 {
		t.Errorf("bytes = %v", got["bytes"])
	}
	freq, err := app.ByteFreq(p, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(freq) != 1 || freq[0].Byte != 0 || freq[0].Count != 1024 {
		t.Errorf("freq = %+v", freq)
	}
	if _, err := app.EntropyOf(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing file")
	}
}

func TestHexCalc(t *testing.T) {
	app := newTestApp(t)
	got, err := app.HexCalc("0x10 * 2 + 1")
	if err != nil {
		t.Fatal(err)
	}
	if got["dec"] != "33" {
		t.Errorf("dec = %s", got["dec"])
	}
	if got["hex"] != "0x21" {
		t.Errorf("hex = %s", got["hex"])
	}
	if got["bytes"] != "1" {
		t.Errorf("bytes = %s", got["bytes"])
	}
	if _, err := app.HexCalc("1/0"); err == nil {
		t.Error("division by zero accepted")
	}
	// Larger results need more bytes.
	got, _ = app.HexCalc("0x10000")
	if got["bytes"] != "4" {
		t.Errorf("4-byte result: %s", got["bytes"])
	}
}

func TestRegexAndStrings(t *testing.T) {
	app := newTestApp(t)
	p := filepath.Join(t.TempDir(), "d.bin")
	if err := os.WriteFile(p, []byte("foo\x00bar\x00foobar"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := app.RegexTest(p, "foo", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Errorf("regex = %+v", m)
	}
	if _, err := app.RegexTest(p, "", 10); err == nil {
		t.Error("empty pattern")
	}
	if _, err := app.RegexTest(p, "(", 10); err == nil {
		t.Error("bad regex")
	}
	s, err := app.StringsOf(p, 3, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) < 2 {
		t.Errorf("strings = %+v", s)
	}
}

func TestSplitJoinShred(t *testing.T) {
	app := newTestApp(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	os.WriteFile(src, []byte("abcdefghij"), 0o644)
	pattern := filepath.Join(dir, "p-%d.bin")
	parts, err := app.SplitFile(src, pattern, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 3 {
		t.Fatalf("parts = %d", len(parts))
	}
	dst := filepath.Join(dir, "out.bin")
	n, err := app.JoinFiles(parts, dst)
	if err != nil {
		t.Fatal(err)
	}
	if n != 10 {
		t.Errorf("joined = %d", n)
	}
	body, _ := os.ReadFile(dst)
	if string(body) != "abcdefghij" {
		t.Errorf("content = %q", body)
	}
	// Shred removes the file.
	if err := app.Shred(dst, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("shred left the file")
	}
	if _, err := app.SplitFile(filepath.Join(dir, "missing"), pattern, 4); err == nil {
		t.Error("split of missing file")
	}
	if _, err := app.JoinFiles(nil, dst); err == nil {
		t.Error("join with no parts")
	}
}

func TestGenerators(t *testing.T) {
	app := newTestApp(t)
	pw, err := app.PasswordGen(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 16 {
		t.Errorf("pw len = %d", len(pw))
	}
	u1, err := app.UUIDGen()
	if err != nil {
		t.Fatal(err)
	}
	u2, _ := app.UUIDGen()
	if u1 == u2 {
		t.Error("UUIDs collided")
	}
	ul, err := app.ULIDGen()
	if err != nil {
		t.Fatal(err)
	}
	if len(ul) != 26 {
		t.Errorf("ulid len = %d", len(ul))
	}
	hex1, err := app.RandomHex(8)
	if err != nil {
		t.Fatal(err)
	}
	if len(hex1) != 16 {
		t.Errorf("hex len = %d", len(hex1))
	}
	hex2, _ := app.RandomHex(8)
	if hex1 == hex2 {
		t.Error("random hex collided")
	}
}

func TestTimestampConvert(t *testing.T) {
	app := newTestApp(t)
	got, err := app.TimestampConvert(0, "s")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got["utc"], "1970-01-01") {
		t.Errorf("utc = %q", got["utc"])
	}
	if _, err := app.TimestampConvert(0, "parsecs"); err == nil {
		t.Error("bad unit accepted")
	}
}

func TestExportPNG(t *testing.T) {
	app := newTestApp(t)
	src := filepath.Join(t.TempDir(), "d.bin")
	if err := os.WriteFile(src, []byte("Hello, PNG export!"), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := app.OpenFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "out.png")
	res, err := app.ExportPNG(doc.ID, 0, doc.Size, 2, dst)
	if err != nil {
		t.Fatal(err)
	}
	if res.BytesSaved == 0 {
		t.Fatal("empty png")
	}
	body, _ := os.ReadFile(dst)
	if !strings.HasPrefix(string(body), "\x89PNG") {
		t.Errorf("not a png: %q", body[:8])
	}
	if _, err := app.ExportPNG(doc.ID, 0, 1<<25, 2, dst); err == nil {
		t.Error("oversized export accepted")
	}
	if _, err := app.ExportPNG(999999, 0, 4, 2, dst); err == nil {
		t.Error("bad doc id accepted")
	}
	if _, err := app.ExportPNG(doc.ID, -1, 4, 2, dst); err == nil {
		t.Error("negative offset accepted")
	}
}
