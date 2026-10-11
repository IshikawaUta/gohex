package fs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// fakeExt builds an extFS backed by a byte image with the given block size.
func fakeExt(img []byte, block int64) *extFS {
	return &extFS{block: block, r: rangeReader{src: memReader{img}, size: int64(len(img))}}
}

// extentHeader writes an in-page extent tree header (12 bytes).
func extentHeader(node []byte, entries, max, depth uint16) {
	binary.LittleEndian.PutUint16(node[0:], 0xF30A)
	binary.LittleEndian.PutUint16(node[2:], entries)
	binary.LittleEndian.PutUint16(node[4:], max)
	binary.LittleEndian.PutUint16(node[6:], depth)
}

// extentLeaf writes a leaf extent entry: logical blocks, n blocks, phys.
func extentLeaf(node []byte, i int, logical uint32, n uint16, phys uint32) {
	off := 12 + i*12
	binary.LittleEndian.PutUint32(node[off:], logical)
	binary.LittleEndian.PutUint16(node[off+4:], n)
	binary.LittleEndian.PutUint32(node[off+8:], phys)
}

// extentIdx writes an index extent entry pointing at child block leaf.
func extentIdx(node []byte, i int, logical uint32, leaf uint64) {
	off := 12 + i*12
	binary.LittleEndian.PutUint32(node[off:], logical)
	binary.LittleEndian.PutUint32(node[off+4:], uint32(leaf))
	binary.LittleEndian.PutUint16(node[off+8:], uint16(leaf>>32))
}

func TestExtentTreeLeaf(t *testing.T) {
	e := fakeExt(make([]byte, 1<<16), 4096)
	node := make([]byte, 60)
	extentHeader(node, 2, 4, 0)
	extentLeaf(node, 0, 10, 2, 100)
	extentLeaf(node, 1, 20, 1, 200)
	got, err := e.extentTree(node, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].logical != 10*4096 || got[0].length != 2*4096 || got[0].phys != 100 {
		t.Fatalf("entry0=%+v", got[0])
	}
	if got[1].logical != 20*4096 || got[1].phys != 200 {
		t.Fatalf("entry1=%+v", got[1])
	}
}

func TestExtentTreeUninitSkipped(t *testing.T) {
	e := fakeExt(make([]byte, 1<<16), 4096)
	node := make([]byte, 60)
	extentHeader(node, 2, 4, 0)
	extentLeaf(node, 0, 5, 0x8003, 70) // uninitialized
	extentLeaf(node, 1, 9, 1, 71)
	got, err := e.extentTree(node, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].logical != 9*4096 || got[0].phys != 71 {
		t.Fatalf("got=%+v", got)
	}
}

func TestExtentTreeIndex(t *testing.T) {
	img := make([]byte, 1<<16)
	e := fakeExt(img, 4096)
	// Child leaf block at block 3.
	child := make([]byte, 4096)
	extentHeader(child, 1, 4, 0)
	extentLeaf(child, 0, 2, 3, 7)
	copy(img[3*4096:], child)

	node := make([]byte, 60)
	extentHeader(node, 1, 4, 1) // depth 1 = index
	extentIdx(node, 0, 5, 3)
	got, err := e.extentTree(node, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("len=%d", len(got))
	}
	// Child logical 2 is relative to parent base 5 → (5+2)*block.
	if got[0].logical != 7*4096 || got[0].length != 3*4096 || got[0].phys != 7 {
		t.Fatalf("got=%+v", got[0])
	}
}

func TestExtentTreeErrors(t *testing.T) {
	img := make([]byte, 1<<16)
	e := fakeExt(img, 4096)

	t.Run("bad magic", func(t *testing.T) {
		node := make([]byte, 60)
		if _, err := e.extentTree(node, 0); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("implausible count", func(t *testing.T) {
		node := make([]byte, 60)
		extentHeader(node, 9, 4, 0)
		if _, err := e.extentTree(node, 0); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("too deep", func(t *testing.T) {
		node := make([]byte, 60)
		extentHeader(node, 0, 4, 0)
		if _, err := e.extentTree(node, 6); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("child read error", func(t *testing.T) {
		node := make([]byte, 60)
		extentHeader(node, 1, 4, 1)
		extentIdx(node, 0, 0, 1<<40) // way beyond image
		if _, err := e.extentTree(node, 0); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("truncated entry", func(t *testing.T) {
		node := make([]byte, 16) // header + partial entry
		extentHeader(node, 4, 4, 0)
		got, err := e.extentTree(node, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("got=%+v", got)
		}
	})
	t.Run("empty", func(t *testing.T) {
		node := make([]byte, 60)
		extentHeader(node, 0, 4, 0)
		got, err := e.extentTree(node, 0)
		if err != nil || len(got) != 0 {
			t.Fatalf("got=%+v err=%v", got, err)
		}
	})
}

// inodeBuf builds a fake raw ext inode with 128-byte i_block space.
func inodeBuf(size uint32, direct map[int]uint32, indirect map[int]uint32) []byte {
	b := make([]byte, 128)
	binary.LittleEndian.PutUint16(b[0:], 0x81A4)
	binary.LittleEndian.PutUint32(b[4:], size)
	binary.LittleEndian.PutUint16(b[26:], 1)
	for i, v := range direct {
		binary.LittleEndian.PutUint32(b[40+i*4:], v)
	}
	for i, v := range indirect {
		binary.LittleEndian.PutUint32(b[40+i*4:], v)
	}
	return b
}

// indirectBlock writes an array of data/indirect block pointers.
func indirectBlock(img []byte, block int64, ptrs []uint32) {
	off := block * 4096
	for i, p := range ptrs {
		binary.LittleEndian.PutUint32(img[off+int64(i)*4:], p)
	}
}

func TestIndirectTreeDirectAndHole(t *testing.T) {
	img := make([]byte, 1<<20)
	e := fakeExt(img, 4096)
	indirectBlock(img, 40, []uint32{41, 42})
	b := inodeBuf(12288, map[int]uint32{0: 40, 2: 42}, nil)
	got, err := e.indirectTree(b, 0, 0, 12288)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d %+v", len(got), got)
	}
	if got[0].logical != 0 || got[0].phys != 40 {
		t.Fatalf("got[0]=%+v", got[0])
	}
	// Direct slot 1 is 0 → hole → logical 1 is unmapped, slot 2 maps to 42.
	if got[1].logical != 8192 || got[1].phys != 42 {
		t.Fatalf("got[1]=%+v", got[1])
	}
}

func TestIndirectTreeSingleAndDouble(t *testing.T) {
	img := make([]byte, 1<<20)
	e := fakeExt(img, 4096)
	// Single indirect block 50 → data blocks.
	indirectBlock(img, 50, []uint32{60, 0, 62})
	// Double indirect: block 51 → [single 52, 0, 54]; block 52 → [70].
	indirectBlock(img, 51, []uint32{52, 0, 54})
	indirectBlock(img, 52, []uint32{70})
	indirectBlock(img, 54, []uint32{71})

	b := inodeBuf(16<<20, map[int]uint32{}, map[int]uint32{12: 50, 13: 51})
	got, err := e.indirectTree(b, 0, 0, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	// Direct slots all 0 → 12 holes → logical 12*4096 = single-indirect base.
	base := int64(12 * 4096)
	per := int64(1024)
	want := []extBlock{
		{logical: base, length: 4096, phys: 60},
		{logical: base + 2*4096, length: 4096, phys: 62},
		// double-indirect base = base + block*per = base + 4MiB
		{logical: base + 4096*per, length: 4096, phys: 70},
		{logical: base + 4096*per + 2*4096*per, length: 4096, phys: 71},
	}
	if len(got) != len(want) {
		t.Fatalf("len=%d %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%+v want %+v", i, got[i], want[i])
		}
	}
}

func TestIndirectTreeDepthCapped(t *testing.T) {
	e := fakeExt(make([]byte, 1<<20), 4096)
	got, err := e.indirectTree(make([]byte, 128), 4, 0, 0)
	if err != nil || got != nil {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestIndirectTreeReadError(t *testing.T) {
	e := fakeExt(make([]byte, 1<<20), 4096)
	b := inodeBuf(4096, map[int]uint32{}, map[int]uint32{12: 100000})
	if _, err := e.indirectTree(b, 0, 0, 4096); err == nil {
		t.Fatal("expected error")
	}
}

func TestWalkIndirectReadError(t *testing.T) {
	e := fakeExt(make([]byte, 1<<20), 4096)
	var out []extBlock
	if err := e.walkIndirect(1<<40, 0, 0, 4096, &out); err == nil {
		t.Fatal("expected error")
	}
	if err := e.walkIndirect(1<<40, 1, 0, 4096, &out); err == nil {
		t.Fatal("expected error")
	}
}

func TestReadBlockError(t *testing.T) {
	e := fakeExt(make([]byte, 1<<20), 4096)
	if err := e.readBlock(make([]byte, 4096), 1<<40); err == nil {
		t.Fatal("expected error")
	}
}

// --- readAt hole semantics -------------------------------------------------

func readAtHelper(t *testing.T, e *extFS, n extInode, off int64, want int) ([]byte, error) {
	t.Helper()
	p := make([]byte, want)
	_, err := e.readAt(n, off, p)
	return p, err
}

func TestReadAtHolesAndReads(t *testing.T) {
	img := make([]byte, 1<<20)
	e := fakeExt(img, 4096)
	// Distinct patterns in blocks 100 and 103.
	pat0 := bytes.Repeat([]byte{0xAA}, 4096)
	pat1 := bytes.Repeat([]byte{0xBB}, 1000)
	copy(img[100*4096:], pat0)
	copy(img[103*4096:], pat1)

	n := extInode{
		size: 4096 + 4096*2 + 1000, // hole between 4096 and 12288
		links: []extBlock{
			{logical: 0, length: 4096, phys: 100},
			{logical: 12288, length: 1000, phys: 103},
		},
	}

	// Read spanning block → hole → block (exercises the fall-through fix).
	p, err := readAtHelper(t, e, n, 0, len(img) /* big enough */)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if !bytes.Equal(p[:4096], pat0) {
		t.Fatal("first block mismatch")
	}
	for i := 4096; i < 12288; i++ {
		if p[i] != 0 {
			t.Fatalf("hole byte %d = %#x", i, p[i])
		}
	}
	if !bytes.Equal(p[12288:12288+1000], pat1) {
		t.Fatal("second block mismatch after hole")
	}
}

func TestReadAtEdges(t *testing.T) {
	img := make([]byte, 1<<20)
	e := fakeExt(img, 4096)
	copy(img[5*4096:], bytes.Repeat([]byte{0xCC}, 4096))
	n := extInode{size: 4096, links: []extBlock{{logical: 0, length: 4096, phys: 5}}}

	if _, err := e.readAt(n, 4096, make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("off==size: %v", err)
	}
	// Short read at EOF → io.EOF with partial fill.
	p, err := readAtHelper(t, e, n, 4094, 10)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("short: %v", err)
	}
	if !bytes.Equal(p[:2], []byte{0xCC, 0xCC}) || p[2] != 0 {
		t.Fatalf("p=%x", p)
	}
	// Trailing hole (size larger than last extent).
	n2 := extInode{size: 9000, links: []extBlock{{logical: 0, length: 4096, phys: 5}}}
	p, err = readAtHelper(t, e, n2, 4096, 100)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	for i, b := range p {
		if b != 0 {
			t.Fatalf("trailing hole byte %d = %#x", i, b)
		}
	}
	// Read error: phys block beyond image.
	n3 := extInode{size: 4096, links: []extBlock{{logical: 0, length: 4096, phys: 1 << 30}}}
	if _, err := e.readAt(n3, 0, make([]byte, 10)); err == nil {
		t.Fatal("expected error")
	}
}

func TestReadAtSkipsEarlierBlocks(t *testing.T) {
	img := make([]byte, 1<<20)
	e := fakeExt(img, 4096)
	copy(img[7*4096:], bytes.Repeat([]byte{0xDD}, 4096))
	n := extInode{
		size:  8192,
		links: []extBlock{{logical: 0, length: 4096, phys: 5}, {logical: 4096, length: 4096, phys: 7}},
	}
	// Reading inside block 1 must skip block 0 entirely (off >= end).
	p, _ := readAtHelper(t, e, n, 4096, 16)
	if !bytes.Equal(p, bytes.Repeat([]byte{0xDD}, 16)) {
		t.Fatalf("p=%x", p)
	}
}
