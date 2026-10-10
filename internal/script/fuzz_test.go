package script

import (
	"context"
	"testing"
	"time"
)

// fuzzHost is a minimal Host implementation: one tiny document, no matches.
// It satisfies the surface scripts can reach without any real service state.
type fuzzHost struct{}

func (fuzzHost) Docs() []Doc {
	return []Doc{{ID: 1, Name: "fuzz.bin", Size: 32}}
}

func (fuzzHost) Read(id, offset, size int64) ([]byte, error) {
	if size < 0 {
		size = 0
	}
	if size > 4096 {
		size = 4096
	}
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(i)
	}
	return out, nil
}

func (fuzzHost) Find(id int64, text string, offset int64, limit int) ([]int64, error) {
	if limit > 8 {
		limit = 8
	}
	return nil, nil
}

// FuzzRun fuzzes Starlark script source text. Sources are capped at 4 KiB
// and every run is bounded by both the runner's step limit and an outer
// 250 ms context timeout, so a mutated infinite loop cannot stall the
// fuzzing process.
func FuzzRun(f *testing.F) {
	f.Add([]byte("print(gohex.version())\n"))
	f.Add([]byte("docs = gohex.docs()\nprint(len(docs))\n"))
	f.Add([]byte("data = gohex.read(1, 0, 8)\nprint(len(data))\n"))
	f.Add([]byte("print(gohex.hash('SHA-256', b'abc'))\n"))
	f.Add([]byte("for i in range(100):\n  pass\n"))
	f.Add([]byte("this is not python"))
	f.Add([]byte("while True:\n  pass\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, src []byte) {
		if len(src) > 4096 {
			t.Skip("script source too large")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		_, _ = Run(ctx, fuzzHost{}, "fuzz.star", src)
	})
}
