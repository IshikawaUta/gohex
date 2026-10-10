package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStartCloneAsync(t *testing.T) {
	app := newTestApp(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	body := make([]byte, 512<<10)
	for i := range body {
		body[i] = byte(i)
	}
	if err := os.WriteFile(src, body, 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "clone.bin")
	st, err := app.StartClone(CloneRequest{SrcPath: src, DstPattern: dst})
	if err != nil {
		t.Fatal(err)
	}
	if st.State != "running" {
		t.Fatalf("state = %s", st.State)
	}
	// Wait for completion (poll; the job is small).
	deadline := time.Now().Add(10 * time.Second)
	var final CloneJobStatus
	for time.Now().Before(deadline) {
		final, err = app.CloneStatus(st.ID)
		if err != nil {
			t.Fatal(err)
		}
		if final.State == "done" || final.State == "error" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if final.State != "done" {
		t.Fatalf("final state = %s err=%s", final.State, final.Error)
	}
	if final.Copied != int64(len(body)) {
		t.Errorf("copied = %d", final.Copied)
	}
	got, _ := os.ReadFile(dst)
	if len(got) != len(body) {
		t.Errorf("dest size = %d", len(got))
	}
	// Listed and audited.
	list := app.CloneList()
	if len(list) != 1 {
		t.Errorf("list = %d", len(list))
	}
	logged := caseAudit(t, app)
	if !strings.Contains(logged, `"op":"clone"`) {
		t.Errorf("audit log missing clone:\n%s", logged)
	}
}

func TestStartCloneValidation(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.StartClone(CloneRequest{}); err == nil {
		t.Error("empty request accepted")
	}
	dir := t.TempDir()
	if _, err := app.StartClone(CloneRequest{SrcPath: filepath.Join(dir, "missing"), DstPattern: filepath.Join(dir, "d")}); err == nil {
		t.Error("missing source accepted")
	}
	if err := os.Mkdir(filepath.Join(dir, "adir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := app.StartClone(CloneRequest{SrcPath: filepath.Join(dir, "adir"), DstPattern: filepath.Join(dir, "d")}); err == nil {
		t.Error("directory source accepted")
	}
	src := filepath.Join(dir, "src.bin")
	os.WriteFile(src, []byte("x"), 0o644)
	if _, err := app.StartClone(CloneRequest{SrcPath: src, DstPattern: src}); err == nil {
		t.Error("same src/dst accepted")
	}
	if _, err := app.CloneStatus(99999); err == nil {
		t.Error("unknown job id accepted")
	}
	if err := app.CancelClone(99999); err == nil {
		t.Error("cancel unknown job accepted")
	}
}

func TestStartCloneCancel(t *testing.T) {
	app := newTestApp(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	// 8 MiB so the copy takes a few iterations.
	if err := os.WriteFile(src, make([]byte, 8<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "clone.bin")
	st, err := app.StartClone(CloneRequest{SrcPath: src, DstPattern: dst})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.CancelClone(st.ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	var final CloneJobStatus
	for time.Now().Before(deadline) {
		final, _ = app.CloneStatus(st.ID)
		if final.State == "done" || final.State == "error" || final.State == "cancelled" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The fast in-memory copy may finish before the cancel lands;
	// either done or cancelled is acceptable, error is not.
	if final.State == "error" {
		t.Fatalf("cancelled job errored: %s", final.Error)
	}
}
