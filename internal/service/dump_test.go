package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IshikawaUta/gohex/internal/audit"
)

const testTombstone = `*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'google/sdk_gphone64/emu64:14/UE1A:userdebug/dev-keys'
Timestamp: 2026-10-10 12:00:00.123456789+0000
Cmdline: com.example.app
pid: 42, tid: 42, name: com.example.app  >>> com.example.app <<<
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0

backtrace:
      #00 pc 0000000000045abc  /apex/com.android.runtime/lib64/bionic/libc.so (memcpy+188)
`

func TestDumpInfo(t *testing.T) {
	app := newTestApp(t)
	path := writeFile(t, "tombstone.txt", []byte(testTombstone))

	rep, err := app.DumpInfo(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Source != "android" || rep.Format != "tombstone" ||
		rep.App != "com.example.app" || rep.Type != "SIGSEGV" || rep.Frames != 1 {
		t.Fatalf("rep = %+v", rep)
	}

	events, err := audit.ReadAll(app.log.Path(), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == audit.ActionOpen && e.Detail["op"] == "dump" &&
			e.Detail["format"] == "tombstone" && e.Result == audit.ResultOK {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit record for dump parse; events = %+v", events)
	}
}

func TestDumpInfoErrors(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.DumpInfo(""); err == nil {
		t.Fatal("empty path should fail")
	}
	if _, err := app.DumpInfo(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Fatal("missing file should fail")
	}
	bogus := writeFile(t, "bogus.ips", []byte("plain text, not a report\n"))
	if _, err := app.DumpInfo(bogus); err == nil ||
		!strings.Contains(err.Error(), "unrecognized") {
		t.Fatalf("unrecognized report: %v", err)
	}
	oversize := writeFile(t, "big.ips", nil)
	f, err := os.OpenFile(oversize, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(make([]byte, maxDumpReport+1)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := app.DumpInfo(oversize); err == nil ||
		!strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversize report: %v", err)
	}
}
