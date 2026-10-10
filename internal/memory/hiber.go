package memory

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// Windows hibernation file page signatures (hiberfil.sys). Each 4 KiB
// page begins with one of these 4-byte magics followed by a version
// dword. The page bodies are XPRESS-Huffman compressed; only the page
// inventory is parsed here.
const (
	hiberPageSize  = 4096
	hiberMaxPages  = 1 << 20 // 4 GiB of pages — plenty for inventory
	hiberScanLimit = 1 << 16 // stop the scan after 256k pages
)

var hiberMagics = []string{"HIBR", "hibr", "PAGR", "page", "PAGF", "hibf"}

// probeHiber inventories a Windows hibernation file. It requires the
// first page to carry a known magic, then walks consecutive pages
// counting signatures and versions. The payload decompression is not
// supported; the returned info is a triage summary only.
func probeHiber(f readerAtSize) *HiberInfo {
	var head [8]byte
	if _, err := f.ReadAt(head[:], 0); err != nil {
		return nil
	}
	if !isHiberMagic(head[:4]) {
		return nil
	}
	info := &HiberInfo{PageSize: hiberPageSize}
	versions := map[uint32]int{}
	var page [hiberPageSize]byte
	for i := 0; i < hiberScanLimit; i++ {
		off := int64(i) * hiberPageSize
		n, err := f.ReadAt(page[:], off)
		if err != nil && n < 4 {
			break
		}
		if !isHiberMagic(page[:4]) {
			break // inventory stops at the first non-signature page
		}
		ver := binary.LittleEndian.Uint32(page[4:8])
		versions[ver]++
		info.Pages++
		if info.Pages >= hiberMaxPages {
			break
		}
	}
	if info.Pages == 0 {
		return nil
	}
	for v, n := range versions {
		info.Versions = append(info.Versions, fmt.Sprintf("%s x%d", hiberVersionName(v), n))
	}
	sort.Strings(info.Versions)
	return info
}

func isHiberMagic(b []byte) bool {
	for _, m := range hiberMagics {
		if string(b) == m {
			return true
		}
	}
	return false
}

func hiberVersionName(v uint32) string {
	return fmt.Sprintf("v%d", v)
}
