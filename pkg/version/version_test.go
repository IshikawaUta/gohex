package version

import "testing"

func TestVersionSemVerShape(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must not be empty")
	}
	if Product != "GoHex" {
		t.Fatalf("Product = %q, want GoHex", Product)
	}
}
