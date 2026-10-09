package service

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/IshikawaUta/gohex/internal/audit"
)

func TestScriptRunReadsOpenDoc(t *testing.T) {
	app := newTestApp(t)
	data := []byte("Hello, GoHex! Hello again!")
	info, err := app.OpenFile(writeFile(t, "evidence.bin", data))
	if err != nil {
		t.Fatal(err)
	}

	scriptPath := writeFile(t, "report.star", []byte(`
docs = gohex.docs()
print("docs", len(docs))
d = docs[0]
print("name", d.name, "size", d.size)
print("head", gohex.read(d.id, 0, 5))
print("hits", gohex.find(d.id, "Hello", limit=10))
print("hash", gohex.hash(gohex.read(d.id, 0, 25), "sha256"))
print("ver", gohex.version())
`))

	res, err := app.ScriptRun(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if res.Error != "" {
		t.Fatalf("script error: %s", res.Error)
	}
	if res.Steps == 0 {
		t.Error("Steps = 0")
	}
	for _, want := range []string{
		"docs 1",
		"name evidence.bin size 26",
		"head Hello",
		"hits [0, 14]",
		"ver GoHex ",
	} {
		if !strings.Contains(res.Output, want) {
			t.Errorf("output missing %q:\n%s", want, res.Output)
		}
	}
	if res.DurationMs < 0 {
		t.Errorf("DurationMs = %d", res.DurationMs)
	}

	events, err := audit.ReadAll(app.log.Path(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == audit.ActionScript && e.Result == audit.ResultOK &&
			e.Target == scriptPath && e.Detail["mode"] == "read-only" {
			found = true
		}
	}
	if !found {
		t.Errorf("no script-run audit event; events = %+v", events)
	}
	_ = info
}

func TestScriptRunFailureIsInResult(t *testing.T) {
	app := newTestApp(t)
	scriptPath := writeFile(t, "bad.star", []byte("print(\"before\")\n[1][5]\n"))
	res, err := app.ScriptRun(scriptPath)
	if err != nil {
		t.Fatalf("script failure should not be a Go error: %v", err)
	}
	if !strings.Contains(res.Error, "script:") || !strings.Contains(res.Error, "out of range") {
		t.Errorf("res.Error = %q", res.Error)
	}
	if !strings.Contains(res.Output, "before") {
		t.Errorf("output before failure lost: %q", res.Output)
	}

	events, _ := audit.ReadAll(app.log.Path(), nil)
	found := false
	for _, e := range events {
		if e.Action == audit.ActionScript && e.Result == audit.ResultError {
			found = true
		}
	}
	if !found {
		t.Errorf("no script-run error audit event")
	}
}

func TestScriptRunInfrastructureErrors(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.ScriptRun(""); err == nil {
		t.Error("empty path: err = nil")
	}
	if _, err := app.ScriptRun("/nonexistent/script.star"); err == nil {
		t.Error("missing file: err = nil")
	}
	if _, err := app.ScriptRun(t.TempDir()); err == nil {
		t.Error("directory: err = nil")
	}
	big := writeFile(t, "big.star", bytes.Repeat([]byte("#"), maxScriptSize+1))
	if _, err := app.ScriptRun(big); err == nil {
		t.Error("oversized script: err = nil")
	} else if !strings.Contains(err.Error(), "limit") {
		t.Errorf("err = %v, want size-limit message", err)
	}
}

func TestScriptHostClampsAndErrors(t *testing.T) {
	app := newTestApp(t)
	info, err := app.OpenFile(writeFile(t, "evidence.bin", []byte("0123456789")))
	if err != nil {
		t.Fatal(err)
	}

	// Read past the end of the document returns the bytes that exist; a
	// short tail read is not an error.
	p := writeFile(t, "clamp.star", []byte("print(len(gohex.read("+itoa(info.ID)+", 6, 100)))\nprint(len(gohex.read("+itoa(info.ID)+", 20, 4)))\n"))
	res, err := app.ScriptRun(p)
	if err != nil {
		t.Fatal(err)
	}
	if res.Error != "" {
		t.Fatalf("script error: %s", res.Error)
	}
	if !strings.Contains(res.Output, "4\n0") {
		t.Errorf("output = %q, want 4 then 0", res.Output)
	}

	// Unknown document ids and empty patterns surface as script errors.
	for _, src := range []string{
		"gohex.read(999, 0, 4)\n",
		"gohex.find(999, \"x\")\n",
		"gohex.find(" + itoa(info.ID) + ", \"\")\n",
	} {
		p := writeFile(t, "err.star", []byte(src))
		res, err := app.ScriptRun(p)
		if err != nil {
			t.Fatal(err)
		}
		if res.Error == "" {
			t.Errorf("script %q: res.Error empty, want error", src)
		}
	}
}

func TestScriptHostFindOnEmptyDoc(t *testing.T) {
	app := newTestApp(t)
	info := app.NewDocument() // untitled, empty
	p := writeFile(t, "empty.star", []byte("print(gohex.find("+itoa(info.ID)+", \"x\"))\n"))
	res, err := app.ScriptRun(p)
	if err != nil {
		t.Fatal(err)
	}
	if res.Error != "" {
		t.Fatalf("script error: %s", res.Error)
	}
	if !strings.Contains(res.Output, "[]") {
		t.Errorf("output = %q, want []", res.Output)
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }
