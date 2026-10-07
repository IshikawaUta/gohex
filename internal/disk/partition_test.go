package disk

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

// memReader adapts a byte slice to the Reader interface.
type memReader struct{ b []byte }

func (m memReader) Size() int64 { return int64(len(m.b)) }
func (m memReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.b)) {
		return 0, io.EOF
	}
	n := copy(p, m.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func mbrEntry(status, typ byte, lba, count uint32) [16]byte {
	e := [16]byte{}
	e[0] = status
	e[4] = typ
	binary.LittleEndian.PutUint32(e[8:12], lba)
	binary.LittleEndian.PutUint32(e[12:16], count)
	return e
}

func mbrSector(entries [4][16]byte, diskSig uint32) []byte {
	s := make([]byte, SectorSize)
	binary.LittleEndian.PutUint32(s[440:444], diskSig)
	for i, e := range entries {
		copy(s[446+i*16:], e[:])
	}
	s[510], s[511] = 0x55, 0xAA
	return s
}

// guidBytes parses "8-4-4-4-12" into mixed-endian on-disk form.
func guidBytes(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		panic("bad GUID in test: " + s)
	}
	out := make([]byte, 16)
	out[0], out[1], out[2], out[3] = b[3], b[2], b[1], b[0]
	out[4], out[5] = b[5], b[4]
	out[6], out[7] = b[7], b[6]
	copy(out[8:], b[8:])
	return out
}

func utf16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r < 0x10000 {
			out = append(out, byte(r), byte(r>>8))
		}
	}
	return append(out, 0, 0)
}

type gptEnt struct {
	typ   string
	uniq  string
	first uint64
	last  uint64
	label string
}

// buildGPT assembles sector0 (protective MBR) + LBA1 header + LBA2 entries.
func buildGPT(diskSectors uint64, ents []gptEnt, fixHeaderCRC, fixEntriesCRC bool) []byte {
	// Protective MBR.
	pe := mbrEntry(0x00, 0xEE, 1, uint32(min64(diskSectors-1, 0xffffffff)))
	disk := mbrSector([4][16]byte{pe}, 0x12345678)
	disk = append(disk, make([]byte, SectorSize)...) // LBA 1 header
	disk = append(disk, make([]byte, SectorSize)...) // LBA 2+ entries

	entrySize := 128
	table := make([]byte, entrySize*len(ents))
	for i, e := range ents {
		slot := table[i*entrySize:]
		copy(slot[0:16], guidBytes(e.typ))
		copy(slot[16:32], guidBytes(e.uniq))
		binary.LittleEndian.PutUint64(slot[32:40], e.first)
		binary.LittleEndian.PutUint64(slot[40:48], e.last)
		copy(slot[56:], utf16LE(e.label))
	}
	entriesCRC := crc32IEEE(table)
	if !fixEntriesCRC {
		entriesCRC ^= 0xdeadbeef
	}
	copy(disk[2*SectorSize:], table)

	h := disk[SectorSize : 2*SectorSize]
	copy(h[0:8], []byte("EFI PART"))
	binary.LittleEndian.PutUint32(h[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(h[12:16], 92)
	binary.LittleEndian.PutUint64(h[24:32], 1)              // current LBA
	binary.LittleEndian.PutUint64(h[32:40], diskSectors-1)  // backup LBA
	binary.LittleEndian.PutUint64(h[40:48], 34)             // first usable
	binary.LittleEndian.PutUint64(h[48:56], diskSectors-34) // last usable
	copy(h[56:72], guidBytes("11111111-2222-3333-4444-555555555555"))
	binary.LittleEndian.PutUint64(h[72:80], 2) // entries LBA
	binary.LittleEndian.PutUint32(h[80:84], uint32(len(ents)))
	binary.LittleEndian.PutUint32(h[84:88], uint32(entrySize))
	binary.LittleEndian.PutUint32(h[88:92], entriesCRC)
	if fixHeaderCRC {
		crc := crc32IEEE(h[:92])
		binary.LittleEndian.PutUint32(h[16:20], crc)
	} else {
		binary.LittleEndian.PutUint32(h[16:20], 0x11111111)
	}
	// Pad to the full disk size so bounds checks see a realistic medium.
	if uint64(len(disk)) < diskSectors*SectorSize {
		disk = append(disk, make([]byte, int(diskSectors*SectorSize)-len(disk))...)
	}
	return disk
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

const (
	efiType  = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
	msData   = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
	linuxFs  = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
	unique1  = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
	unique2  = "11111111-2222-3333-4444-555555555556"
	diskSize = 64 * 1024 * 1024 // 64 MiB test disk
)

func TestParseNoSignature(t *testing.T) {
	src := memReader{make([]byte, 4096)}
	tab, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if tab.Kind != KindNone || len(tab.Partitions) != 0 {
		t.Fatalf("got kind=%s partitions=%d", tab.Kind, len(tab.Partitions))
	}
}

func TestParseMBRPrimary(t *testing.T) {
	e1 := mbrEntry(0x80, 0x07, 2048, 4096) // NTFS, bootable
	e2 := mbrEntry(0x00, 0x83, 8192, 1024) // Linux
	sec := mbrSector([4][16]byte{e1, e2}, 0xcafebabe)
	buf := make([]byte, diskSize)
	copy(buf, sec)
	src := memReader{buf}

	tab, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if tab.Kind != KindMBR {
		t.Fatalf("kind=%s", tab.Kind)
	}
	if tab.MBRDiskSig != 0xcafebabe {
		t.Fatalf("sig=%#x", tab.MBRDiskSig)
	}
	if len(tab.Partitions) != 2 {
		t.Fatalf("partitions=%d", len(tab.Partitions))
	}
	p := tab.Partitions[0]
	if p.Name != "NTFS/exFAT/HPFS" || p.Start != 2048*512 || p.Size != 4096*512 || !p.Bootable || !p.Primary {
		t.Fatalf("p0=%+v", p)
	}
	p2 := tab.Partitions[1]
	if p2.Name != "Linux" || p2.Start != 8192*512 || p2.Size != 1024*512 || p2.Bootable {
		t.Fatalf("p1=%+v", p2)
	}
	if len(tab.Warnings) != 0 {
		t.Fatalf("warnings=%v", tab.Warnings)
	}
}

func TestParseMBRExtended(t *testing.T) {
	// Disk: 64 MiB = 131072 sectors.
	// Primary extended: type 0x0F at LBA 4096, count 126976.
	// EBR1 at LBA 4096: link rel=8192 (EBR2 at 12288), logical rel=63 (LBA 4159), type 0x07.
	// EBR2 at LBA 12288: link=0, logical rel=63 (LBA 12351), type 0x83.
	ext := mbrEntry(0x00, 0x0F, 4096, 126976)
	sec := mbrSector([4][16]byte{ext}, 0)

	buf := make([]byte, diskSize)
	copy(buf, sec)

	ebr1 := make([]byte, SectorSize)
	e1link := mbrEntry(0x00, 0x0F, 8192, 0)
	e1part := mbrEntry(0x00, 0x07, 63, 4096)
	copy(ebr1[446:], e1link[:])
	copy(ebr1[446+16:], e1part[:])
	ebr1[510], ebr1[511] = 0x55, 0xAA
	copy(buf[4096*512:], ebr1)

	ebr2 := make([]byte, SectorSize)
	e2link := mbrEntry(0x00, 0x00, 0, 0)
	e2part := mbrEntry(0x80, 0x83, 63, 8192)
	copy(ebr2[446:], e2link[:])
	copy(ebr2[446+16:], e2part[:])
	ebr2[510], ebr2[511] = 0x55, 0xAA
	copy(buf[12288*512:], ebr2)

	tab, err := Parse(memReader{buf})
	if err != nil {
		t.Fatal(err)
	}
	if tab.Kind != KindMBR {
		t.Fatalf("kind=%s", tab.Kind)
	}
	if len(tab.Partitions) != 2 {
		t.Fatalf("partitions=%d: %+v", len(tab.Partitions), tab.Partitions)
	}
	p0 := tab.Partitions[0]
	if p0.Primary || p0.Start != 4159*512 || p0.Size != 4096*512 || p0.Name != "NTFS/exFAT/HPFS" {
		t.Fatalf("logical0=%+v", p0)
	}
	p1 := tab.Partitions[1]
	if p1.Primary || p1.Start != 12351*512 || p1.Size != 8192*512 || p1.Name != "Linux" || !p1.Bootable {
		t.Fatalf("logical1=%+v", p1)
	}
}

func TestParseProtectiveWithoutGPT(t *testing.T) {
	pe := mbrEntry(0x00, 0xEE, 1, 1000)
	sec := mbrSector([4][16]byte{pe}, 7)
	// LBA1 has no EFI PART signature (zeros).
	buf := append([]byte{}, sec...)
	buf = append(buf, make([]byte, SectorSize)...)
	tab, err := Parse(memReader{buf})
	if err != nil {
		t.Fatal(err)
	}
	if tab.Kind != KindMBR {
		t.Fatalf("kind=%s", tab.Kind)
	}
	if len(tab.Warnings) == 0 || !strings.Contains(tab.Warnings[0], "protective") {
		t.Fatalf("warnings=%v", tab.Warnings)
	}
	if len(tab.Partitions) != 1 || tab.Partitions[0].Name != "GPT protective" {
		t.Fatalf("partitions=%+v", tab.Partitions)
	}
}

func TestParseGPTValid(t *testing.T) {
	sectors := uint64(diskSize / 512)
	disk := buildGPT(sectors, []gptEnt{
		{efiType, unique1, 34, 2081, "EFI System Partition"},
		{msData, unique2, 4096, 32767, "Data"},
		{linuxFs, "99999999-8888-7777-6666-555555555555", 40000, 60000, ""},
	}, true, true)
	if uint64(len(disk)) != sectors*512 {
		t.Fatalf("disk len %d", len(disk))
	}
	tab, err := Parse(memReader{disk})
	if err != nil {
		t.Fatal(err)
	}
	if tab.Kind != KindGPT {
		t.Fatalf("kind=%s", tab.Kind)
	}
	if tab.DiskGUID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("diskguid=%s", tab.DiskGUID)
	}
	if len(tab.Partitions) != 3 {
		t.Fatalf("partitions=%d %+v", len(tab.Partitions), tab.Partitions)
	}
	if len(tab.Warnings) != 0 {
		t.Fatalf("warnings=%v", tab.Warnings)
	}
	p0 := tab.Partitions[0]
	if p0.Name != "EFI System Partition" { // label overrides type name
		t.Fatalf("p0 name=%q", p0.Name)
	}
	if p0.TypeGUID != "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" {
		t.Fatalf("p0 typeguid=%s", p0.TypeGUID)
	}
	if p0.Start != 34*512 || p0.Size != (2081-34+1)*512 {
		t.Fatalf("p0 range=%d..+%d", p0.Start, p0.Size)
	}
	p1 := tab.Partitions[1]
	if p1.Name != "Data" || p1.PartGUID != "11111111-2222-3333-4444-555555555556" {
		t.Fatalf("p1=%+v", p1)
	}
	p2 := tab.Partitions[2]
	if p2.Label != "" || p2.Name != "Linux filesystem" { // no label -> type name
		t.Fatalf("p2=%+v", p2)
	}
}

func TestParseGPTBadEntriesCRC(t *testing.T) {
	sectors := uint64(diskSize / 512)
	disk := buildGPT(sectors, []gptEnt{
		{msData, unique1, 34, 1000, "Data"},
	}, true, false)
	tab, err := Parse(memReader{disk})
	if err != nil {
		t.Fatal(err)
	}
	if tab.Kind != KindGPT || len(tab.Partitions) != 1 {
		t.Fatalf("tab=%+v", tab)
	}
	found := false
	for _, w := range tab.Warnings {
		if strings.Contains(w, "entry CRC") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no entry CRC warning: %v", tab.Warnings)
	}
}

func TestParseGPTBadHeaderCRC(t *testing.T) {
	sectors := uint64(diskSize / 512)
	disk := buildGPT(sectors, []gptEnt{
		{msData, unique1, 34, 1000, "Data"},
	}, false, true)
	tab, err := Parse(memReader{disk})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range tab.Warnings {
		if strings.Contains(w, "header CRC") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no header CRC warning: %v", tab.Warnings)
	}
}

func TestParseGPTEntryPastEndClamped(t *testing.T) {
	sectors := uint64(diskSize / 512)
	disk := buildGPT(sectors, []gptEnt{
		{msData, unique1, 34, sectors + 1000, "Huge"}, // beyond disk
	}, true, true)
	tab, err := Parse(memReader{disk})
	if err != nil {
		t.Fatal(err)
	}
	if len(tab.Partitions) != 1 {
		t.Fatalf("partitions=%d", len(tab.Partitions))
	}
	p := tab.Partitions[0]
	if p.Start+p.Size > int64(len(disk)) {
		t.Fatalf("not clamped: %+v", p)
	}
	if len(tab.Warnings) == 0 {
		t.Fatal("expected clamp warning")
	}
}

func TestParseSourceTooSmall(t *testing.T) {
	if _, err := Parse(memReader{make([]byte, 100)}); err == nil {
		t.Fatal("expected error for tiny source")
	}
}

func TestParseGPTAllEmptyFallsBack(t *testing.T) {
	sectors := uint64(diskSize / 512)
	disk := buildGPT(sectors, nil, true, true) // zero entries
	// numEntries=0 -> implausible geometry -> error -> MBR fallback
	tab, err := Parse(memReader{disk})
	if err != nil {
		t.Fatal(err)
	}
	if tab.Kind != KindMBR {
		t.Fatalf("kind=%s", tab.Kind)
	}
}

func TestGUIDStrRoundtrip(t *testing.T) {
	g := guidStr(guidBytes("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"))
	if g != "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" {
		t.Fatalf("got %s", g)
	}
}

func TestUTF16Name(t *testing.T) {
	if got := utf16Name(utf16LE("EFI System")); got != "EFI System" {
		t.Fatalf("got %q", got)
	}
	if got := utf16Name([]byte{'A', 0, 0, 0, 'B', 0}); got != "A" {
		t.Fatalf("NUL stop: %q", got)
	}
}

func TestMBRTypeNameUnknown(t *testing.T) {
	if got := mbrTypeName(0x77); got != "Type 0x77" {
		t.Fatalf("got %q", got)
	}
}
