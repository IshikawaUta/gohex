package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestVersionFlagSmoke builds the real binary and checks the two
// contract points that must never regress: -version prints and exits
// zero, and a non-loopback -listen is refused (exit non-zero, reason
// on stderr). Everything else is covered by internal/restapi's
// httptest suite; this pins the command wiring itself.
func TestVersionFlagSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := filepath.Join(t.TempDir(), "gohex-server")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	out, err := exec.Command(bin, "-version").CombinedOutput()
	if err != nil {
		t.Fatalf("-version: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) == "" {
		t.Error("-version printed nothing")
	}

	// Non-loopback bind must be refused before any socket opens.
	cmd := exec.Command(bin, "-listen", "8.8.8.8:9", "-token", "t")
	cmd.Env = append(cmd.Environ(), "GOHEX_SERVER_TOKEN=t")
	refused, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("non-loopback listen was not refused:\n%s", refused)
	}
	if !strings.Contains(strings.ToLower(string(refused)), "loopback") {
		t.Errorf("refusal reason missing 'loopback':\n%s", refused)
	}
}
