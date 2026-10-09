package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersionAndUsage(t *testing.T) {
	if code, out, _ := runCLI(t, "version"); code != 0 || !strings.Contains(out, "gohex-cli") {
		t.Fatalf("version: code=%d out=%q", code, out)
	}
	if code, _, errb := runCLI(t); code != 2 || !strings.Contains(errb, "Usage:") {
		t.Fatalf("usage: code=%d err=%q", code, errb)
	}
	if code, _, errb := runCLI(t, "bogus"); code != 2 || !strings.Contains(errb, "unknown command") {
		t.Fatalf("unknown: code=%d err=%q", code, errb)
	}
}

func TestHash(t *testing.T) {
	p := writeTemp(t, "blob.bin", []byte("hello gohex"))
	code, out, errb := runCLI(t, "hash", p)
	if code != 0 {
		t.Fatalf("hash: code=%d err=%q", code, errb)
	}
	if got := strings.TrimSpace(out); got != "ba39950d05657026bc4ec82b1174bd13cfbfbdb6085d8054e1e611a0657bc5ba" {
		t.Fatalf("sha256 = %q", got)
	}
	if code, out, _ := runCLI(t, "hash", "-algo", "md5", p); code != 0 || len(strings.TrimSpace(out)) != 32 {
		t.Fatalf("md5: code=%d out=%q", code, out)
	}
	if code, _, errb := runCLI(t, "hash", "-algo", "nope", p); code != 1 || !strings.Contains(errb, "unknown") {
		t.Fatalf("bad algo: code=%d err=%q", code, errb)
	}
	if code, _, _ := runCLI(t, "hash"); code != 2 {
		t.Fatalf("missing file: code=%d", code)
	}
}

func TestInfoAndSearch(t *testing.T) {
	data := []byte{0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02}
	p := writeTemp(t, "img.raw", data)
	code, out, errb := runCLI(t, "info", p)
	if code != 0 {
		t.Fatalf("info: code=%d err=%q", code, errb)
	}
	if !strings.Contains(out, "format\traw") || !strings.Contains(out, "size\t8") {
		t.Fatalf("info out = %q", out)
	}

	code, out, errb = runCLI(t, "search", "-hex", "DE AD ?? EF", p)
	if code != 0 {
		t.Fatalf("search: code=%d err=%q", code, errb)
	}
	if !strings.Contains(out, "0x0000000000000002") {
		t.Fatalf("search out = %q", out)
	}

	if code, _, _ := runCLI(t, "search", "-hex", "CA FE", p); code != 3 {
		t.Fatalf("no match: code=%d", code)
	}
	if code, _, errb := runCLI(t, "search", p); code != 2 || !strings.Contains(errb, "-hex") {
		t.Fatalf("missing pattern: code=%d err=%q", code, errb)
	}
	if code, _, errb := runCLI(t, "search", "-hex", "AA", "-text", "x", p); code != 2 {
		t.Fatalf("both patterns: code=%d err=%q", code, errb)
	}
	// UTF-16LE text search.
	p16 := writeTemp(t, "u16.raw", []byte{'p', 0, 'a', 0, 's', 0, 's', 0})
	code, out, errb = runCLI(t, "search", "-text", "pass", "-enc", "utf16le", p16)
	if code != 0 || !strings.Contains(out, "0x0000000000000000") {
		t.Fatalf("utf16 search: code=%d out=%q err=%q", code, out, errb)
	}
	if code, _, errb := runCLI(t, "search", "-text", "x", "-enc", "ebcdic", p16); code != 2 {
		t.Fatalf("bad enc: code=%d err=%q", code, errb)
	}
}
