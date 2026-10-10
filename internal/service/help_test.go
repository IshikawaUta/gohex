package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShortcutHelpTable(t *testing.T) {
	app := newTestApp(t)
	rows := app.ShortcutHelp()
	if len(rows) == 0 {
		t.Fatal("empty table")
	}
	var found bool
	for _, r := range rows {
		if r.Action == "goto.offset" && r.Default == "Ctrl+G" && r.Bound == "Ctrl+G" {
			found = true
		}
	}
	if !found {
		t.Fatalf("goto.offset row missing or wrong: %+v", rows[:min(5, len(rows))])
	}
}

func TestCreateSampleFile(t *testing.T) {
	app := newTestApp(t)
	dst := filepath.Join(t.TempDir(), "sample.bin")
	res, err := app.CreateSampleFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if res.BytesSaved != 64<<10 || res.SHA256 == "" {
		t.Fatalf("res=%+v", res)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(data[0:2]) != "MZ" {
		t.Fatalf("missing MZ header: %q", data[:2])
	}
	// Overwrite refused.
	if _, err := app.CreateSampleFile(dst); err == nil {
		t.Fatal("overwrite accepted")
	}
	if _, err := app.CreateSampleFile(""); err == nil {
		t.Fatal("empty dst accepted")
	}
}
