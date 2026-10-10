package fs

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// syntheticFAT builds a small but structurally valid FAT12 image entirely in
// memory (no external mkfs tool needed), so benchmarks and fuzz seeds can
// share one deterministic fixture. The layout is: boot sector, two FAT
// copies, a root directory and nFiles one-cluster files, half of them inside
// a single subdirectory so a recursive walk has something to descend into.
//
// The image is nFiles+2 clusters plus the fixed areas, which keeps it under
// the FAT12/FAT16 boundary (4085 clusters) for every practical nFiles.
func syntheticFAT(nFiles int) []byte {
	if nFiles < 1 {
		nFiles = 1
	}
	const (
		secSize  = 512
		reserved = 1
		nFATs    = 2
	)
	if nFiles > 4080 {
		nFiles = 4080 // stay inside FAT12
	}
	rootEntries := 16
	for rootEntries < nFiles+2 {
		rootEntries += 16 // directory entries never straddle a sector boundary
	}
	rootSectors := rootEntries * 32 / secSize
	// Clusters: nFiles for the root files, one for the subdirectory and one
	// for the file inside it. Clusters are numbered from 2.
	clusterCnt := nFiles + 2
	fatEntries := clusterCnt + 2
	fatBytes := (fatEntries*3 + 1) / 2
	fatSectors := (fatBytes + secSize - 1) / secSize
	dataStart := reserved + nFATs*fatSectors + rootSectors
	totSectors := dataStart + clusterCnt
	if totSectors*secSize < 4096 { // fs.Probe rejects ranges below 4 KiB
		totSectors = 4096 / secSize
	}

	img := make([]byte, totSectors*secSize)

	// Boot sector (BPB + the fields newFAT reads).
	b := img[:secSize]
	b[0], b[1], b[2] = 0xEB, 0x3C, 0x90
	copy(b[3:11], "GOHEX   ")
	binary.LittleEndian.PutUint16(b[11:13], secSize)
	b[13] = 1 // sectors per cluster
	binary.LittleEndian.PutUint16(b[14:16], reserved)
	b[16] = nFATs
	binary.LittleEndian.PutUint16(b[17:19], uint16(rootEntries))
	binary.LittleEndian.PutUint16(b[19:21], uint16(totSectors))
	b[21] = 0xF8 // media descriptor
	binary.LittleEndian.PutUint16(b[22:24], uint16(fatSectors))
	binary.LittleEndian.PutUint16(b[24:26], 63)
	binary.LittleEndian.PutUint16(b[26:28], 255)
	b[38] = 0x29
	binary.LittleEndian.PutUint32(b[39:43], 0x20261010)
	copy(b[43:54], "GHEXTEST  ")
	copy(b[54:62], "FAT12   ")
	b[510], b[511] = 0x55, 0xAA

	// FAT copies: entries 0/1 are the reserved media entries, every used
	// chain is a single cluster ending in the FAT12 EOC marker.
	fat := make([]byte, fatSectors*secSize)
	putFat12 := func(clus int, v uint16) {
		i := clus * 3 / 2
		if clus&1 == 0 {
			fat[i] = byte(v)
			fat[i+1] = fat[i+1]&0xF0 | byte(v>>8)
		} else {
			fat[i] = fat[i]&0x0F | byte(v<<4)
			fat[i+1] = byte(v >> 4)
		}
	}
	putFat12(0, 0xFFF8)
	putFat12(1, 0xFFFF)
	for i := 0; i < clusterCnt; i++ {
		putFat12(i+2, 0xFFF)
	}
	copy(img[secSize*reserved:], fat)
	copy(img[secSize*(reserved+fatSectors):], fat)

	// Root directory: every file, then the subdirectory.
	rootOff := secSize * (reserved + nFATs*fatSectors)
	subDirClus := uint16(nFiles + 2)
	innerClus := uint16(nFiles + 3)
	pos := rootOff
	for i := 1; i <= nFiles; i++ {
		copy(img[pos:], fat12Entry(fmt.Sprintf("F%07d.TXT", i), 0x20, uint16(i+1), 512))
		pos += 32
	}
	copy(img[pos:], fat12Entry("SUBDIR     ", 0x10, subDirClus, 0))

	// Subdirectory contents: two files sharing one cluster.
	dirOff := secSize * (dataStart + int(subDirClus-2))
	copy(img[dirOff:], fat12Entry("INNER   TXT", 0x20, innerClus, 512))
	copy(img[dirOff+32:], fat12Entry("NOTE    TXT", 0x20, innerClus, 512))

	// File payloads, one cluster each (the subdirectory cluster is skipped:
	// it holds directory entries instead).
	for i := 2; i <= clusterCnt+1; i++ {
		off := secSize * (dataStart + i - 2)
		if off+secSize > len(img) {
			break
		}
		if i == int(subDirClus) {
			continue
		}
		copy(img[off:], fmt.Sprintf("payload of cluster %d\n", i))
	}
	return img
}

// fat12Entry packs one 8.3 directory entry the way fatParseDir reads it.
func fat12Entry(name11 string, attr byte, clus uint16, size uint32) []byte {
	var e [32]byte
	copy(e[0:11], name11)
	e[11] = attr
	binary.LittleEndian.PutUint16(e[26:28], clus)
	binary.LittleEndian.PutUint32(e[28:32], size)
	return e[:]
}

// walkList recursively lists every directory below path, returning the number
// of entries seen. It is the shape of workload the UI's tree pane issues.
func walkList(f FS, path string) (int, error) {
	ents, err := f.List(path)
	if err != nil {
		return 0, err
	}
	total := len(ents)
	for _, e := range ents {
		if e.Dir {
			n, err := walkList(f, e.Path)
			if err != nil {
				return total, err
			}
			total += n
		}
	}
	return total, nil
}

// BenchmarkFsList measures a full recursive directory walk over a generated
// FAT12 image: Probe once, then List per directory.
func BenchmarkFsList(b *testing.B) {
	img := syntheticFAT(64)
	src := memReader{img}
	for _, bc := range []struct {
		name string
		path string
	}{
		{"root", "/"},
		{"subdir", "/SUBDIR"},
		{"recursive", "(walk)"},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.SetBytes(int64(len(img)))
			for i := 0; i < b.N; i++ {
				f, err := Probe(src, 0, int64(len(img)))
				if err != nil {
					b.Fatal(err)
				}
				if bc.path == "(walk)" {
					if _, err := walkList(f, "/"); err != nil {
						b.Fatal(err)
					}
					continue
				}
				if _, err := f.List(bc.path); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
