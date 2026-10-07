package disk

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"unicode/utf16"
)

func crc32IEEE(b []byte) uint32 { return crc32.ChecksumIEEE(b) }

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// guidStr formats a 16-byte EFI GUID (mixed-endian on disk) in canonical
// 8-4-4-4-12 lowercase form.
func guidStr(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	d := binary.LittleEndian.Uint32(b[0:4])
	e := binary.LittleEndian.Uint16(b[4:6])
	f := binary.LittleEndian.Uint16(b[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d, e, f, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// utf16Name decodes a UTF-16LE name field, stopping at the first NUL.
func utf16Name(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i : i+2])
		if v == 0 {
			break
		}
		u = append(u, v)
	}
	return string(utf16.Decode(u))
}

// mbrTypeName maps a classic MBR partition type byte to a display label.
func mbrTypeName(t byte) string {
	switch t {
	case 0x01:
		return "FAT12"
	case 0x04:
		return "FAT16"
	case 0x06:
		return "FAT16B"
	case 0x07:
		return "NTFS/exFAT/HPFS"
	case 0x0B:
		return "FAT32"
	case 0x0C:
		return "FAT32 (LBA)"
	case 0x0E:
		return "FAT16 (LBA)"
	case 0x11:
		return "Hidden FAT12"
	case 0x14:
		return "Hidden FAT16"
	case 0x16:
		return "Hidden FAT16B"
	case 0x1B:
		return "Hidden FAT32"
	case 0x1C:
		return "Hidden FAT32 (LBA)"
	case 0x27:
		return "Windows recovery"
	case 0x2A:
		return "AOS / Boot manager"
	case 0x39:
		return "Plan 9"
	case 0x41:
		return "PowerPC PReP"
	case 0x63:
		return "Unix / GNU HURD"
	case 0x81:
		return "Linux"
	case 0x82:
		return "Linux swap"
	case 0x83:
		return "Linux"
	case 0x84:
		return "Hibernation"
	case 0x8E:
		return "Linux LVM"
	case 0xA5:
		return "FreeBSD / NetBSD / OpenBSD"
	case 0xA8:
		return "macOS"
	case 0xA9:
		return "NetBSD"
	case 0xAB:
		return "macOS boot"
	case 0xAF:
		return "macOS HFS/HFS+"
	case 0xBE:
		return "Solaris boot"
	case 0xBF:
		return "Solaris"
	case 0xEB:
		return "BeOS"
	case 0xED:
		return "GRUB2 RAID"
	case 0xEE:
		return "GPT protective"
	case 0xEF:
		return "EFI system"
	default:
		return fmt.Sprintf("Type %#02x", t)
	}
}

// wellKnownGPT contains canonical (uppercase-canonical here, compared
// case-insensitively) GPT type GUIDs users actually encounter.
var wellKnownGPT = map[string]string{
	"c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI system",
	"e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft reserved",
	"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft basic data",
	"de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows recovery",
	"0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
	"6523f877-0199-4742-a0b7-200e050ff57b": "Linux swap",
	"44479540-f297-41b2-9af7-d131d5f0458a": "Linux LVM",
	"0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux /home",
	"21686148-6449-6e6f-744e-656564454649": "BIOS boot",
	"8da63339-0007-60c0-c434-000000000000": "BIOS boot (alt)",
	"9fc6bad4-3ebe-4e62-91ba-8dbadb9fb9c6": "Android kernel",
	"49a4d17f-93a3-45c1-a0de-f50b2ebe2599": "Android fastboot",
	"83bd6b9d-7f41-11dc-be0b-001560b84f0f": "FreeBSD boot",
	"516e7cb4-6ecf-11d3-853f-91e915b93cb0": "FreeBSD/UFS",
	"48465300-0000-11aa-aa11-00306543ecac": "HPFS/APFS",
	"7c3457ef-0000-11aa-aa11-00306543ecac": "CoreStorage",
}

func gptTypeName(typeGUID []byte) string {
	g := guidStr(typeGUID)
	if n, ok := wellKnownGPT[g]; ok {
		return n
	}
	return "GPT " + g
}
