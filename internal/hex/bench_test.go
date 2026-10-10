package hex

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/IshikawaUta/gohex/internal/core"
)

// BenchmarkReadWindow pages fixed-size windows out of a 16 MiB document of
// random bytes — the access pattern of the hex view scrolling through a
// file. Random content keeps the page cache honest (a sparse file would be
// served from the zero page).
func BenchmarkReadWindow(b *testing.B) {
	const total = 16 << 20
	path := filepath.Join(b.TempDir(), "window.img")
	data := make([]byte, total)
	rnd := rand.New(rand.NewSource(0x600D))
	rnd.Read(data)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		b.Fatal(err)
	}
	src, err := core.OpenFile(path)
	if err != nil {
		b.Fatal(err)
	}
	doc := New(src)
	defer doc.Close()

	for _, win := range []int{4 << 10, 64 << 10, 1 << 20} {
		b.Run(fmt.Sprintf("%dB", win), func(b *testing.B) {
			b.SetBytes(int64(win))
			span := total - win
			for i := 0; i < b.N; i++ {
				off := int64((i * win) % span)
				if _, err := doc.ReadCopy(off, int64(win)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
