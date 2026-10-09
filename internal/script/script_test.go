package script

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fakeHost serves fixed documents to scripts.
type fakeHost struct {
	docs []Doc
	data map[int64][]byte
	// findHits is what Find returns, ignoring the pattern.
	findHits []int64
	findErr  error
	readErr  error
}

func (h *fakeHost) Docs() []Doc { return h.docs }

func (h *fakeHost) Read(id, offset, size int64) ([]byte, error) {
	if h.readErr != nil {
		return nil, h.readErr
	}
	b := h.data[id]
	if offset >= int64(len(b)) {
		return nil, nil
	}
	end := offset + size
	if end > int64(len(b)) {
		end = int64(len(b))
	}
	return b[offset:end], nil
}

func (h *fakeHost) Find(_ int64, _ string, _ int64, _ int) ([]int64, error) {
	return h.findHits, h.findErr
}

func testHost() *fakeHost {
	return &fakeHost{
		docs: []Doc{
			{ID: 1, Name: "evidence.bin", Size: 16},
			{ID: 2, Name: "ram.lime", Size: 4096},
		},
		data: map[int64][]byte{
			1: []byte("Hello, GoHex!!!!"),
		},
		findHits: []int64{0, 8},
	}
}

func TestRunDocsReadFindHash(t *testing.T) {
	src := `
docs = gohex.docs()
print("docs", len(docs))
d = docs[0]
print("first", d.name, d.size)
data = gohex.read(d.id, 0, 5)
print("head", data)
print("hash", gohex.hash(data, "sha256"))
hits = gohex.find(d.id, "Hello", limit=10)
print("hits", hits)
print("ver", gohex.version())
`
	res, err := Run(context.Background(), testHost(), "test.star", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"docs 2",
		"first evidence.bin 16",
		"head Hello",
		"hash 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
		"hits [0, 8]",
		"ver GoHex ",
	} {
		if !strings.Contains(res.Output, want) {
			t.Errorf("output missing %q:\n%s", want, res.Output)
		}
	}
	if res.Steps == 0 {
		t.Error("Steps = 0, want a nonzero step count")
	}
}

func TestRunOutputPreservedOnFailure(t *testing.T) {
	// Starlark rejects undefined names at compile time, so use a runtime
	// failure (index out of range) to prove output before the error sticks.
	res, err := Run(context.Background(), testHost(), "bad.star",
		[]byte("print(\"before\")\n[1][5]\n"))
	if err == nil || !strings.Contains(err.Error(), "script:") {
		t.Fatalf("err = %v, want script-prefixed error", err)
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("error should name the failing expression: %v", err)
	}
	if !strings.Contains(res.Output, "before") {
		t.Errorf("output before the failure should be preserved: %q", res.Output)
	}
}

func TestRunSyntaxError(t *testing.T) {
	_, err := Run(context.Background(), testHost(), "syn.star", []byte("def broken(:\n"))
	if err == nil || !strings.Contains(err.Error(), "script:") {
		t.Fatalf("err = %v, want script-prefixed error", err)
	}
}

func TestRunStepLimit(t *testing.T) {
	start := time.Now()
	_, err := Run(context.Background(), testHost(), "loop.star",
		[]byte("def loop():\n    i = 0\n    while True:\n        i += 1\nloop()\n"))
	if err == nil {
		t.Fatal("infinite loop: err = nil")
	}
	if !strings.Contains(err.Error(), "too many steps") {
		t.Errorf("err = %v, want step-limit error", err)
	}
	if time.Since(start) > DefaultTimeout+time.Second {
		t.Errorf("step limit did not stop the loop promptly: %v", time.Since(start))
	}
}

func TestRunSandbox(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want string
	}{
		{"no-load", `load("os", "x")`, "disabled"},
		{"no-open", `open("/etc/passwd")`, "undefined"},
		{"no-import", `import("os")`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Run(context.Background(), testHost(), "sbox.star", []byte(tc.src))
			if err == nil {
				t.Fatal("err = nil, want error")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunHostErrors(t *testing.T) {
	if _, err := Run(context.Background(), nil, "x.star", []byte("pass")); err == nil {
		t.Error("nil host: err = nil")
	}
	h := testHost()
	h.readErr = context.DeadlineExceeded
	_, err := Run(context.Background(), h, "x.star", []byte("gohex.read(1, 0, 4)"))
	if err == nil || !strings.Contains(err.Error(), "gohex.read") {
		t.Errorf("read error = %v, want gohex.read-wrapped", err)
	}
	h = testHost()
	h.findErr = context.Canceled
	_, err = Run(context.Background(), h, "x.star", []byte("gohex.find(1, \"x\")"))
	if err == nil || !strings.Contains(err.Error(), "gohex.find") {
		t.Errorf("find error = %v, want gohex.find-wrapped", err)
	}
}

func TestReadArgumentValidation(t *testing.T) {
	h := testHost()
	for _, src := range []string{
		"gohex.read(1, -1, 4)",
		"gohex.read(1, 0, -1)",
		"gohex.read(1, 0, 1 << 30)",
		"gohex.read(1)",
	} {
		if _, err := Run(context.Background(), h, "a.star", []byte(src)); err == nil {
			t.Errorf("%s: err = nil, want error", src)
		}
	}
	// A short read past the end returns the bytes that exist.
	res, err := Run(context.Background(), h, "a.star", []byte("print(len(gohex.read(1, 12, 100)))"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Output, "4") {
		t.Errorf("output = %q, want 4", res.Output)
	}
}

func TestFindArgumentValidation(t *testing.T) {
	h := testHost()
	for _, src := range []string{
		"gohex.find(1, \"\")",
		"gohex.find(1, \"x\", offset=-2)",
		"gohex.find(1, \"" + strings.Repeat("a", MaxPatternLen+1) + "\")",
	} {
		if _, err := Run(context.Background(), h, "a.star", []byte(src)); err == nil {
			t.Errorf("validation: err = nil for %q", src[:40])
		}
	}
}

func TestHashAlgo(t *testing.T) {
	h := testHost()
	// sha256("Hello") — known vector.
	res, err := Run(context.Background(), h, "h.star",
		[]byte("print(gohex.hash(b\"Hello\", \"sha256\"))\nprint(gohex.hash(b\"Hello\"))"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Output, "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969") {
		t.Errorf("sha256 vector missing:\n%s", res.Output)
	}
	if _, err := Run(context.Background(), h, "h.star", []byte("gohex.hash(b\"x\", \"nope\")")); err == nil {
		t.Error("unknown algo: err = nil")
	}
}

func TestOutputCap(t *testing.T) {
	src := "for i in range(200000):\n    print(\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\")\n"
	res, err := Run(context.Background(), testHost(), "cap.star", []byte(src))
	// The step limit or the output cap stops this; either way output is capped.
	_ = err
	if len(res.Output) > MaxOutput+64 {
		t.Errorf("output length %d exceeds the cap", len(res.Output))
	}
}
