// Package disk parses on-disk partition structures of block devices and raw
// disk images. It is strictly read-only: parsers operate on byte slices and
// never write to the underlying medium.
//
// Supported layouts:
//   - MBR (DOS) partition tables, including extended (EBR) chains
//   - GPT partition tables with header and entry-array CRC verification
//
// The package deliberately contains no filesystem knowledge; probing which
// filesystem lives in a partition belongs to internal/fs.
package disk

import (
	"encoding/binary"
	"fmt"
)

// SectorSize is the logical sector size assumed for partition parsing.
// MBR structures live in the first 512 bytes of LBA 0 even on 4Kn devices,
// and GPT fields are expressed in LBAs that we address with 512-byte units
// (the layout used by every desktop OS today).
const SectorSize = 512

// Kind classifies the partition layout of a disk.
type Kind string

const (
	// KindNone means no partition signature was found (superfloppy or
	// unpartitioned image such as a single-filesystem disk file).
	KindNone Kind = "none"
	// KindMBR means a DOS/MBR partition table (possibly with an extended
	// chain, possibly a protective MBR without a valid GPT).
	KindMBR Kind = "mbr"
	// KindGPT means a GUID Partition Table with a valid header.
	KindGPT Kind = "gpt"
)

// Partition describes a single partition.
type Partition struct {
	// Index is the 0-based position in Table.Partitions.
	Index int `json:"index"`
	// Name is a human-readable type label ("NTFS/exFAT", "EFI system",
	// "Linux", ...). It never contains user data.
	Name string `json:"name"`
	// Start is the byte offset of the partition from the disk start.
	Start int64 `json:"start"`
	// Size is the partition length in bytes.
	Size int64 `json:"size"`
	// Bootable reports the MBR boot-active flag (always false for GPT).
	Bootable bool `json:"bootable"`
	// Primary distinguishes MBR primary partitions from logical ones in
	// an extended chain. Always true for GPT.
	Primary bool `json:"primary"`
	// TypeGUID is the GPT type GUID in canonical form (empty for MBR).
	TypeGUID string `json:"typeGuid,omitempty"`
	// PartGUID is the GPT unique partition GUID (empty for MBR).
	PartGUID string `json:"partGuid,omitempty"`
	// Label is the GPT partition name (UTF-16, empty for MBR).
	Label string `json:"label,omitempty"`
}

// Table is the parsed partition layout of a disk.
type Table struct {
	Kind Kind `json:"kind"`
	// Partitions lists all partitions in disk order (MBR primary entries
	// first, then logical partitions of the extended chain).
	Partitions []Partition `json:"partitions"`
	// DiskGUID is the GPT disk signature GUID (empty for MBR).
	DiskGUID string `json:"diskGuid,omitempty"`
	// MBRDiskSig is the 32-bit MBR disk signature (0x00000000 if unset).
	MBRDiskSig uint32 `json:"mbrDiskSig,omitempty"`
	// Warnings carries non-fatal validation notes (CRC mismatch, entries
	// outside the disk, truncated GPT, ...). A table with warnings is
	// still usable but should be treated with care.
	Warnings []string `json:"warnings,omitempty"`
}

// Parse examines src and returns its partition table. It never returns a
// nil table for a readable source: an unpartitioned disk yields KindNone
// with no partitions. An error is returned only when src is too small to
// hold a boot sector or the boot sector cannot be read.
func Parse(src Reader) (*Table, error) {
	if src.Size() < SectorSize {
		return nil, fmt.Errorf("disk: source too small (%d bytes)", src.Size())
	}
	sector := make([]byte, SectorSize)
	if _, err := src.ReadAt(sector, 0); err != nil {
		return nil, fmt.Errorf("disk: read boot sector: %w", err)
	}
	t := &Table{Kind: KindNone}

	if hasGPTSignature(sector) {
		if err := parseGPT(src, t); err == nil {
			return t, nil
		}
		// fall back to MBR handling (protective MBR or bogus GPT);
		// parseGPT already recorded a warning via the caller below.
	}
	return parseMBR(src, t, sector)
}

// Reader is the minimal read interface disk needs. core.Source satisfies it.
type Reader interface {
	Size() int64
	ReadAt(p []byte, off int64) (int, error)
}

func hasGPTSignature(sector []byte) bool {
	if sector[510] != 0x55 || sector[511] != 0xAA {
		return false
	}
	// Protective MBR marker: at least one 0xEE partition entry.
	for i := 0; i < 4; i++ {
		if sector[446+i*16+4] == 0xEE {
			return true
		}
	}
	return false
}

func parseMBR(src Reader, t *Table, sector []byte) (*Table, error) {
	if sector[510] != 0x55 || sector[511] != 0xAA {
		return t, nil // no partition table at all
	}
	t.Kind = KindMBR
	t.MBRDiskSig = binary.LittleEndian.Uint32(sector[440:444])

	diskSize := src.Size()
	var extendedStart int64 = -1 // byte offset of first EBR, -1 = none

	for i := 0; i < 4; i++ {
		e := sector[446+i*16:]
		typ := e[4]
		if typ == 0 {
			continue
		}
		start := int64(binary.LittleEndian.Uint32(e[8:12])) * SectorSize
		count := int64(binary.LittleEndian.Uint32(e[12:16])) * SectorSize
		bootable := e[0] == 0x80

		switch typ {
		case 0x05, 0x0F, 0x85: // extended containers
			if extendedStart < 0 {
				extendedStart = start
			}
			if start+count > diskSize {
				t.Warnings = append(t.Warnings,
					fmt.Sprintf("extended partition table (type %#02x) extends past end of disk", typ))
			}
		case 0xEE: // protective MBR
			t.Partitions = append(t.Partitions, Partition{
				Index: len(t.Partitions), Name: "GPT protective",
				Start: start, Size: count, Primary: true,
			})
			if t.Kind == KindMBR && !gptPresent(src) {
				t.Warnings = append(t.Warnings, "protective MBR without valid GPT")
			}
		default:
			t.Partitions = append(t.Partitions, Partition{
				Index: len(t.Partitions), Name: mbrTypeName(typ),
				Start: start, Size: count, Bootable: bootable, Primary: true,
			})
		}
	}

	if extendedStart >= 0 {
		parseEBRChain(src, t, extendedStart, diskSize)
	}
	for i := range t.Partitions {
		p := &t.Partitions[i]
		if p.Start >= diskSize {
			t.Warnings = append(t.Warnings,
				fmt.Sprintf("partition %d starts past end of disk", p.Index+1))
			continue
		}
		if p.Start+p.Size > diskSize {
			t.Warnings = append(t.Warnings,
				fmt.Sprintf("partition %d extends past end of disk (clamped)", p.Index+1))
			p.Size = diskSize - p.Start
		}
	}
	return t, nil
}

// parseEBRChain walks the extended boot record chain starting at ebrStart
// (byte offset) and appends every logical partition found. Guards against
// loops and runaway chains.
//
// Layout convention per EBR: entry 0 links to the next EBR (LBA offset
// relative to this EBR); entry 1 holds the logical partition, also with an
// LBA offset relative to this EBR.
func parseEBRChain(src Reader, t *Table, ebrStart int64, diskSize int64) {
	const maxLogical = 128
	next := ebrStart
	for n := 0; n < maxLogical && next > 0 && next+SectorSize <= diskSize; n++ {
		sec := make([]byte, SectorSize)
		if _, err := src.ReadAt(sec, next); err != nil {
			t.Warnings = append(t.Warnings, "extended chain truncated")
			return
		}
		if sec[510] != 0x55 || sec[511] != 0xAA {
			t.Warnings = append(t.Warnings, "extended boot record signature missing")
			return
		}
		link := sec[446:]
		logical := sec[446+16:]
		nextRel := int64(binary.LittleEndian.Uint32(link[8:12])) * SectorSize

		if logical[4] != 0 && !isExtendedType(logical[4]) {
			partRel := int64(binary.LittleEndian.Uint32(logical[8:12])) * SectorSize
			t.Partitions = append(t.Partitions, Partition{
				Index: len(t.Partitions), Name: mbrTypeName(logical[4]),
				Start: next + partRel, Size: cntOf(logical),
				Bootable: logical[0] == 0x80, Primary: false,
			})
		}
		if nextRel == 0 {
			return
		}
		next += nextRel
	}
	t.Warnings = append(t.Warnings, "extended chain too long or looping (stopped)")
}

func isExtendedType(t byte) bool { return t == 0x05 || t == 0x0F || t == 0x85 }

func cntOf(entry []byte) int64 {
	return int64(binary.LittleEndian.Uint32(entry[12:16])) * SectorSize
}

// gptPresent reports whether a valid GPT header sits at LBA 1.
func gptPresent(src Reader) bool {
	h := make([]byte, SectorSize)
	if _, err := src.ReadAt(h, SectorSize); err != nil {
		return false
	}
	return string(h[0:8]) == "EFI PART"
}

func parseGPT(src Reader, t *Table) error {
	hdr := make([]byte, SectorSize)
	if _, err := src.ReadAt(hdr, SectorSize); err != nil {
		return fmt.Errorf("disk: read GPT header: %w", err)
	}
	if string(hdr[0:8]) != "EFI PART" {
		return fmt.Errorf("disk: no GPT header")
	}
	headerSize := binary.LittleEndian.Uint32(hdr[12:16])
	if headerSize < 92 || headerSize > SectorSize {
		return fmt.Errorf("disk: invalid GPT header size %d", headerSize)
	}
	// Header CRC: field at offset 16 must be zeroed during the check.
	stored := binary.LittleEndian.Uint32(hdr[16:20])
	zeroed := make([]byte, headerSize)
	copy(zeroed, hdr[:headerSize])
	binary.LittleEndian.PutUint32(zeroed[16:20], 0)
	if crc32IEEE(zeroed) != stored {
		t.Warnings = append(t.Warnings, "GPT header CRC mismatch")
	}

	numEntries := binary.LittleEndian.Uint32(hdr[80:84])
	entrySize := binary.LittleEndian.Uint32(hdr[84:88])
	entriesLBA := int64(binary.LittleEndian.Uint64(hdr[72:80]))
	entriesCRC := binary.LittleEndian.Uint32(hdr[88:92])
	t.DiskGUID = guidStr(hdr[56:72])

	if numEntries == 0 || numEntries > 4096 || entrySize < 128 || entrySize > 4096 || entrySize%8 != 0 {
		return fmt.Errorf("disk: implausible GPT geometry: %d entries x %d bytes", numEntries, entrySize)
	}
	tableBytes := int64(numEntries) * int64(entrySize)
	if entriesLBA*SectorSize+tableBytes > src.Size() {
		t.Warnings = append(t.Warnings, "GPT entry array extends past end of disk")
		return fmt.Errorf("disk: GPT entries out of bounds")
	}
	raw := make([]byte, tableBytes)
	if _, err := src.ReadAt(raw, entriesLBA*SectorSize); err != nil {
		return fmt.Errorf("disk: read GPT entries: %w", err)
	}
	if crc32IEEE(raw) != entriesCRC {
		t.Warnings = append(t.Warnings, "GPT partition entry CRC mismatch")
	}

	t.Kind = KindGPT
	diskSize := src.Size()
	empty := true
	for i := uint32(0); i < numEntries; i++ {
		e := raw[int64(i)*int64(entrySize):]
		if allZero(e[:16]) {
			continue
		}
		empty = false
		first := int64(binary.LittleEndian.Uint64(e[32:40]))
		last := int64(binary.LittleEndian.Uint64(e[40:48]))
		p := Partition{
			Index:    len(t.Partitions),
			Name:     gptTypeName(e[:16]),
			Start:    first * SectorSize,
			Size:     (last - first + 1) * SectorSize,
			Primary:  true,
			TypeGUID: guidStr(e[0:16]),
			PartGUID: guidStr(e[16:32]),
			Label:    utf16Name(e[56:]),
		}
		if p.Label != "" {
			p.Name = p.Label
		}
		if p.Start < 0 || p.Size <= 0 {
			t.Warnings = append(t.Warnings,
				fmt.Sprintf("GPT entry %d has invalid range", i+1))
			continue
		}
		if p.Start+p.Size > diskSize {
			t.Warnings = append(t.Warnings,
				fmt.Sprintf("GPT partition %d extends past end of disk (clamped)", len(t.Partitions)+1))
			p.Size = diskSize - p.Start
		}
		if p.Size <= 0 {
			t.Warnings = append(t.Warnings,
				fmt.Sprintf("GPT entry %d lies outside the disk", i+1))
			continue
		}
		t.Partitions = append(t.Partitions, p)
	}
	if empty {
		return fmt.Errorf("disk: GPT has no partitions")
	}
	return nil
}
