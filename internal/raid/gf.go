package raid

// gfTables holds the GF(2^8) logarithm/antilog tables used by the
// RAID 6 Q-parity (Reed-Solomon over the byte field with the standard
// 0x11d primitive polynomial, as popularised by the Linux kernel's
// raid6 implementation). The tables are immutable after construction.
type gfTables struct {
	log   [256]byte // log[v] = discrete log of v base α (log[0] unused)
	pow   [512]byte // pow[n] = α^n for n in 0..511 (doubled for cheap reduction)
	gfDeg int       // modulus used for negative exponents (255)
}

func newGFTables() *gfTables {
	t := &gfTables{gfDeg: 255}
	x := byte(1)
	for i := 0; i < 255; i++ {
		t.log[x] = byte(i)
		t.pow[i] = x
		t.pow[i+255] = x
		// x *= α (0x02) in GF(2^8), reducing by 0x11d on overflow.
		if x&0x80 != 0 {
			x = (x << 1) ^ 0x1d
		} else {
			x <<= 1
		}
	}
	t.pow[255] = 1 // α^255 = 1
	t.pow[510] = 1
	t.log[1] = 0
	return t
}

// Pow returns α^n for any integer n (wrapped into 0..254).
func (t *gfTables) Pow(n int) byte {
	n %= 255
	if n < 0 {
		n += 255
	}
	return t.pow[n]
}

// mulConst multiplies dst in place by the constant c.
func (t *gfTables) mulConst(dst []byte, c byte) {
	if c == 1 {
		return
	}
	cl := int(t.log[c])
	for i := range dst {
		if dst[i] == 0 {
			continue
		}
		dst[i] = t.pow[cl+int(t.log[dst[i]])]
	}
}

// mulXor computes dst ^= c · src in GF(2^8), byte by byte. This is
// the RAID 6 syndrome building block.
func (t *gfTables) mulXor(dst, src []byte, c byte) {
	if c == 1 {
		for i := range src {
			dst[i] ^= src[i]
		}
		return
	}
	cl := int(t.log[c])
	for i := range src {
		if src[i] == 0 {
			continue
		}
		dst[i] ^= t.pow[cl+int(t.log[src[i]])]
	}
}
