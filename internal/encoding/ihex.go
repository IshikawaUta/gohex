package bincoding

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// IHEXRecord is one decoded Intel HEX record.
type IHEXRecord struct {
	Type    byte   // 00 data, 01 EOF, 02 ext segment, 03 start segment, 04 ext linear, 05 start linear
	Address uint16 // 16-bit address field
	Data    []byte
	Raw     string // original line, for round-trip display
}

// IHEXImage is the result of decoding an Intel HEX stream: a flat byte image
// plus the origin where address 0 of the image lives.
type IHEXImage struct {
	Data   []byte
	Origin uint64 // absolute address of Data[0]
	EOF    bool
}

// DecodeIntelHex parses an Intel HEX stream (records separated by newlines,
// each starting with ':'). Extended-address records (types 02/04) are applied
// so that data from >64 KiB images lands at the right absolute offset.
// Errata-tolerant: blank lines and a UTF-8 BOM are skipped.
func DecodeIntelHex(r io.Reader) (*IHEXImage, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	img := &IHEXImage{}
	var upper uint64
	first := true
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		line = strings.TrimPrefix(line, "\uFEFF")
		if line == "" {
			continue
		}
		if line[0] != ':' {
			return nil, fmt.Errorf("bincoding: intel hex line %d: missing ':'", lineNo)
		}
		raw, err := HexToBytes(line[1:])
		if err != nil {
			return nil, fmt.Errorf("bincoding: intel hex line %d: %w", lineNo, err)
		}
		if len(raw) < 5 {
			return nil, fmt.Errorf("bincoding: intel hex line %d: truncated record", lineNo)
		}
		count := int(raw[0])
		if len(raw) != count+5 {
			return nil, fmt.Errorf("bincoding: intel hex line %d: length mismatch", lineNo)
		}
		var sum byte
		for _, b := range raw {
			sum += b
		}
		if sum != 0 {
			return nil, fmt.Errorf("bincoding: intel hex line %d: checksum mismatch", lineNo)
		}
		addr := uint16(raw[1])<<8 | uint16(raw[2])
		typ := raw[3]
		data := raw[4 : 4+count]
		switch typ {
		case 0x00: // data
			abs := upper + uint64(addr)
			if first {
				img.Origin = abs
				first = false
			}
			need := int(abs-img.Origin) + len(data)
			if need > len(img.Data) {
				grown := make([]byte, need)
				copy(grown, img.Data)
				img.Data = grown
			}
			copy(img.Data[int(abs-img.Origin):], data)
		case 0x01: // EOF
			img.EOF = true
			return img, nil
		case 0x02: // extended segment address (paragraph * 16)
			if count != 2 {
				return nil, fmt.Errorf("bincoding: intel hex line %d: bad segment record", lineNo)
			}
			upper = (uint64(data[0])<<8 | uint64(data[1])) << 4
		case 0x04: // extended linear address
			if count != 2 {
				return nil, fmt.Errorf("bincoding: intel hex line %d: bad linear record", lineNo)
			}
			upper = uint64(data[0])<<24 | uint64(data[1])<<16
		case 0x03, 0x05: // start address records — informational
		default:
			return nil, fmt.Errorf("bincoding: intel hex line %d: unknown record type %02X", lineNo, typ)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !img.EOF {
		return nil, fmt.Errorf("bincoding: intel hex: missing EOF record")
	}
	return img, nil
}

// EncodeIntelHex converts data into Intel HEX text with extended linear
// address records (type 04) when the address exceeds 64 KiB. Records carry
// up to 16 data bytes — the conventional record length.
func EncodeIntelHex(data []byte, origin uint64) string {
	var sb strings.Builder
	hi := uint64(0xFFFFFFFF)
	for off := 0; off < len(data); {
		abs := origin + uint64(off)
		upper := abs >> 16
		if upper != hi {
			hi = upper
			sb.WriteString(ihexLine(0x04, 0x0000, []byte{byte(hi >> 8), byte(hi)}))
		}
		n := len(data) - off
		if n > 16 {
			n = 16
		}
		// Keep the record inside the 64 KiB address window.
		chunkAddr := uint16(abs & 0xFFFF)
		if (abs&0xFFFF)+uint64(n) > 0x10000 {
			n = int(0x10000 - (abs & 0xFFFF))
		}
		sb.WriteString(ihexLine(0x00, chunkAddr, data[off:off+n]))
		off += n
	}
	sb.WriteString(ihexLine(0x01, 0x0000, nil))
	return sb.String()
}

func ihexLine(typ byte, addr uint16, data []byte) string {
	rec := make([]byte, 0, 5+len(data))
	rec = append(rec, byte(len(data)), byte(addr>>8), byte(addr), typ)
	rec = append(rec, data...)
	var sum byte
	for _, b := range rec {
		sum += b
	}
	rec = append(rec, ^sum+1)
	return ":" + SpacedHex(rec) + "\n"
}
