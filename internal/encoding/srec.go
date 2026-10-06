package bincoding

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// SRecord is one decoded Motorola S-record line.
type SRecord struct {
	Type    byte   // '0'..'9'
	Count   byte   // byte count field
	Address uint64 // decoded address (width depends on record type)
	Data    []byte
	Raw     string
}

// SRecordAddressWidth returns the number of address bytes for an S-record
// type, or 0 for unknown types.
func SRecordAddressWidth(t byte) int {
	switch t {
	case '0', '1', '5', '9':
		return 2
	case '2', '6', '8':
		return 3
	case '3', '7':
		return 4
	}
	return 0
}

// SRecordImage is a decoded S-record program image: flat data plus origin.
type SRecordImage struct {
	Data   []byte
	Origin uint64
	EOF    bool
}

// DecodeSRecords parses a Motorola S-record stream (S0 header, S1/S2/S3 data,
// S5/S6 count, S7/S8/S9 entry point). Records are validated by checksum;
// data records are assembled into a flat image addressed from the first data
// record's origin.
func DecodeSRecords(r io.Reader) (*SRecordImage, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	img := &SRecordImage{}
	first := true
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		line = strings.TrimPrefix(line, "\uFEFF")
		if line == "" {
			continue
		}
		if len(line) < 4 || line[0] != 'S' {
			return nil, fmt.Errorf("bincoding: s-record line %d: missing 'S' prefix", lineNo)
		}
		typ := line[1]
		raw, err := HexToBytes(line[2:])
		if err != nil {
			return nil, fmt.Errorf("bincoding: s-record line %d: %w", lineNo, err)
		}
		if len(raw) < 4 {
			return nil, fmt.Errorf("bincoding: s-record line %d: truncated record", lineNo)
		}
		count := int(raw[0])
		if len(raw) != count+1 {
			return nil, fmt.Errorf("bincoding: s-record line %d: length mismatch", lineNo)
		}
		var sum byte
		for _, b := range raw {
			sum += b
		}
		if sum != 0xFF {
			return nil, fmt.Errorf("bincoding: s-record line %d: checksum mismatch", lineNo)
		}
		aw := SRecordAddressWidth(typ)
		if aw == 0 || 1+aw > len(raw)-1 {
			return nil, fmt.Errorf("bincoding: s-record line %d: unknown type S%c", lineNo, typ)
		}
		var addr uint64
		for i := 0; i < aw; i++ {
			addr = addr<<8 | uint64(raw[1+i])
		}
		data := raw[1+aw : len(raw)-1]
		switch typ {
		case '1', '2', '3': // data
			if first {
				img.Origin = addr
				first = false
			}
			need := int(addr-img.Origin) + len(data)
			if addr < img.Origin {
				return nil, fmt.Errorf("bincoding: s-record line %d: data below origin", lineNo)
			}
			if need > len(img.Data) {
				grown := make([]byte, need)
				copy(grown, img.Data)
				img.Data = grown
			}
			copy(img.Data[int(addr-img.Origin):], data)
		case '7', '8', '9': // entry point / termination
			img.EOF = true
			return img, nil
		case '0', '5', '6': // header & counts — informational
		default:
			return nil, fmt.Errorf("bincoding: s-record line %d: unknown type S%c", lineNo, typ)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !img.EOF {
		return nil, fmt.Errorf("bincoding: s-record: missing termination record")
	}
	return img, nil
}

// EncodeSRecords converts data into an S-record stream: S0 header, S1/S2/S3
// data records chosen by address width, S5 count, and a matching S7/S8/S9
// termination record. Records carry up to 32 data bytes.
func EncodeSRecords(data []byte, origin uint64) string {
	var sb strings.Builder
	sb.WriteString(srecLine('0', 0, []byte("GoHex")))
	aw := 2
	term := byte('9')
	switch {
	case origin+uint64(len(data)) > 0xFFFFFF || origin > 0xFFFFFF:
		aw, term = 4, '7'
	case origin+uint64(len(data)) > 0xFFFF || origin > 0xFFFF:
		aw, term = 3, '8'
	}
	dataTyp := byte('1') + byte(aw-2)
	var count uint64
	for off := 0; off < len(data); {
		n := len(data) - off
		if n > 32 {
			n = 32
		}
		addr := origin + uint64(off)
		sb.WriteString(srecLine(dataTyp, addr, data[off:off+n]))
		off += n
		count++
	}
	if count <= 0xFFFF {
		sb.WriteString(srecLine('5', count, nil))
	}
	sb.WriteString(srecLine(term, origin+uint64(len(data)), nil))
	return sb.String()
}

// srecLine builds one record: STYC C AAAA.. DD.. CC where C is the byte
// count (address bytes + data bytes + checksum), and the checksum is the
// ones' complement of the sum of count, address and data bytes.
func srecLine(typ byte, addr uint64, data []byte) string {
	aw := SRecordAddressWidth(typ)
	if aw == 0 {
		aw = 2
	}
	payload := make([]byte, 0, aw+len(data))
	for i := aw - 1; i >= 0; i-- {
		payload = append(payload, byte(addr>>(8*i)))
	}
	payload = append(payload, data...)
	count := byte(len(payload) + 1)
	var sum byte = count
	for _, b := range payload {
		sum += b
	}
	rec := make([]byte, 0, len(payload)+2)
	rec = append(rec, count)
	rec = append(rec, payload...)
	rec = append(rec, ^sum)
	return "S" + string([]byte{typ}) + SpacedHex(rec) + "\n"
}
