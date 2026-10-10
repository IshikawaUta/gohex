// Package raid implements a read-only RAID 0/1/5/6 interpreter: it
// presents a set of member disks (any io.ReaderAt) as a single logical
// block device. Normal reads do stripe arithmetic; reads that hit a
// missing or unreadable member are reconstructed from parity (RAID 5)
// or double parity (RAID 6, Reed-Solomon over GF(2^8)). Nothing here
// writes to a member — the package is a forensic reader, not a RAID
// controller.
//
// Parity placement is fixed (not rotated): RAID 5 stores P in the
// last member column, RAID 6 stores P and Q in the last two. This is
// the simplest layout to reason about and matches the common
// "first/last parity" arrangements; members and their order are the
// examiner's input, so the mapping is explicit rather than guessed.
package raid

import (
	"errors"
	"fmt"
	"io"
)

// Level is a supported RAID level.
type Level int

const (
	Level0 Level = iota
	Level1
	Level5
	Level6
)

// ParseLevel maps "0"/"1"/"5"/"6" (and "raidN") to a Level.
func ParseLevel(s string) (Level, error) {
	switch s {
	case "0", "raid0", "RAID0":
		return Level0, nil
	case "1", "raid1", "RAID1":
		return Level1, nil
	case "5", "raid5", "RAID5":
		return Level5, nil
	case "6", "raid6", "RAID6":
		return Level6, nil
	}
	return 0, fmt.Errorf("raid: unknown level %q", s)
}

func (l Level) String() string {
	switch l {
	case Level0:
		return "RAID 0"
	case Level1:
		return "RAID 1"
	case Level5:
		return "RAID 5"
	case Level6:
		return "RAID 6"
	}
	return "unknown"
}

// parityDisks returns how many members hold parity for the level.
func (l Level) parityDisks() int {
	switch l {
	case Level5:
		return 1
	case Level6:
		return 2
	}
	return 0
}

// Member is one disk in the array. A nil ReaderAt (or a failed read)
// marks the member as missing; the interpreter then reconstructs from
// parity where the level allows it.
type Member struct {
	io.ReaderAt
	Size int64
	// Missing forces the member to be treated as absent even if
	// ReaderAt is non-nil (useful when a member is known-bad).
	Missing bool
}

// Array is a read-only logical volume over its members.
type Array struct {
	members    []Member
	level      Level
	stripeSize int64
	// dataDisks is how many members hold data per stripe.
	dataDisks int
	// disks is the total member count.
	disks int
	// size is the logical capacity.
	size int64
	// gf tables for RAID 6 Q-parity.
	gf *gfTables
}

// New validates the member layout and computes the logical size.
// stripeSize must be a positive power of two; the member count must
// suit the level (RAID 0/5: ≥2; RAID 1: ≥2; RAID 6: ≥4).
func New(members []Member, level Level, stripeSize int64) (*Array, error) {
	disks := len(members)
	if stripeSize <= 0 || stripeSize&(stripeSize-1) != 0 {
		return nil, errors.New("raid: stripe size must be a positive power of two")
	}
	switch level {
	case Level0, Level1, Level5:
		if disks < 2 {
			return nil, fmt.Errorf("raid: %s needs at least 2 members", level)
		}
	case Level6:
		if disks < 4 {
			return nil, fmt.Errorf("raid: %s needs at least 4 members", level)
		}
	}
	dataDisks := disks - level.parityDisks()
	if dataDisks <= 0 {
		return nil, errors.New("raid: no data disks after reserving parity")
	}
	var size int64
	switch level {
	case Level1:
		size = members[0].Size
		for _, m := range members[1:] {
			if m.Size < size {
				size = m.Size
			}
		}
	default:
		// Capacity = data disks × the bytes each contributes. Each
		// member stores one column of every stripe; the stripe count
		// is limited by the smallest member.
		minMember := members[0].Size
		for _, m := range members[1:] {
			if m.Size < minMember {
				minMember = m.Size
			}
		}
		stripes := minMember / stripeSize
		size = stripes * stripeSize * int64(dataDisks)
	}
	a := &Array{
		members:    members,
		level:      level,
		stripeSize: stripeSize,
		dataDisks:  dataDisks,
		disks:      disks,
		size:       size,
	}
	if level == Level6 {
		a.gf = newGFTables()
	}
	return a, nil
}

// Size is the logical capacity of the array.
func (a *Array) Size() int64 { return a.size }

// StripeSize is the configured stripe unit.
func (a *Array) StripeSize() int64 { return a.stripeSize }

// Level is the array's RAID level.
func (a *Array) Level() Level { return a.level }

// Disks is the member count.
func (a *Array) Disks() int { return a.disks }

// DataDisks is the per-stripe data column count.
func (a *Array) DataDisks() int { return a.dataDisks }

// readMember reads one member, treating a missing member or a read
// error as a failure the caller can reconstruct around. Short reads
// at the member tail are zero-filled so the column length holds.
func (a *Array) readMember(i int, p []byte, off int64) error {
	m := a.members[i]
	if m.Missing || m.ReaderAt == nil {
		return errors.New("raid: member missing")
	}
	total := 0
	for total < len(p) {
		n, err := m.ReadAt(p[total:], off+int64(total))
		total += n
		if err != nil {
			if errors.Is(err, io.EOF) {
				for j := total; j < len(p); j++ {
					p[j] = 0
				}
				return nil
			}
			return err
		}
	}
	return nil
}

// ReadAt implements io.ReaderAt over the logical volume. Reads are
// stripe-granular internally but arbitrary at the API: a read that
// spans stripes is assembled piece by piece. Degraded reads are
// reconstructed transparently; an uncorrectable read (too many
// failures for the level) returns an error naming the stripe.
func (a *Array) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("raid: negative offset")
	}
	if off >= a.size {
		return 0, io.EOF
	}
	limit := len(p)
	if off+int64(limit) > a.size {
		limit = int(a.size - off)
	}
	total := 0
	for total < limit {
		n, err := a.readPartial(p[total:limit], off+int64(total))
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			break
		}
	}
	return total, nil
}

// readPartial reads as much of p as fits in the current stripe.
func (a *Array) readPartial(p []byte, off int64) (int, error) {
	stripeBytes := a.stripeSize * int64(a.dataDisks)
	stripeIdx := off / stripeBytes
	inStripe := off % stripeBytes
	dataIdx := int(inStripe / a.stripeSize)
	inDisk := inStripe % a.stripeSize
	n := len(p)
	if remain := a.stripeSize - inDisk; int64(n) > remain {
		n = int(remain)
	}
	p = p[:n]

	switch a.level {
	case Level0:
		err := a.readMember(dataIdx, p, stripeIdx*a.stripeSize+inDisk)
		return n, err
	case Level1:
		var firstErr error
		for i := range a.members {
			if err := a.readMember(i, p, stripeIdx*a.stripeSize+inDisk); err == nil {
				return n, nil
			} else if firstErr == nil {
				firstErr = err
			}
		}
		return n, firstErr
	case Level5, Level6:
		return a.readStripedParity(p, stripeIdx, dataIdx, inDisk)
	}
	return 0, errors.New("raid: unsupported level")
}

// readStripedParity serves a RAID 5/6 data-column read, reconstructing
// from parity when the owning member is missing or errors.
func (a *Array) readStripedParity(p []byte, stripeIdx int64, dataIdx int, inDisk int64) (int, error) {
	logicalOff := stripeIdx*a.stripeSize + inDisk
	// Fast path: the owning data member is healthy.
	if err := a.readMember(dataIdx, p, logicalOff); err == nil {
		return len(p), nil
	}
	return len(p), a.reconstruct(p, stripeIdx, dataIdx, inDisk)
}

// reconstruct rebuilds one data column of a stripe from the surviving
// members. RAID 5 uses XOR; RAID 6 adds a Reed-Solomon Q column so it
// survives any TWO simultaneous member failures (as long as the
// needed equations remain).
func (a *Array) reconstruct(p []byte, stripeIdx int64, wantData int, inDisk int64) error {
	logicalOff := stripeIdx*a.stripeSize + inDisk
	buf := make([]byte, len(p)*a.disks)
	cols := make([][]byte, a.disks)
	good := 0
	for c := 0; c < a.disks; c++ {
		cols[c] = buf[c*len(p) : (c+1)*len(p)]
		if c == wantData {
			continue // the one we are solving for
		}
		if err := a.readMember(c, cols[c], logicalOff); err == nil {
			good++
		} else {
			cols[c] = nil
		}
	}
	switch a.level {
	case Level5:
		// One equation (XOR) needs every OTHER column intact.
		if good < a.disks-1 {
			return fmt.Errorf("raid: stripe %d uncorrectable (need %d good columns, have %d)", stripeIdx, a.disks-1, good)
		}
		// P = XOR of data columns ⇒ want = P XOR (all other data).
		copy(p, cols[a.dataDisks]) // P column
		for c := 0; c < a.dataDisks; c++ {
			if c != wantData && cols[c] != nil {
				xorInto(p, cols[c])
			}
		}
		return nil
	case Level6:
		// Two equations (P and Q) can solve two unknowns.
		if good < a.disks-2 {
			return fmt.Errorf("raid: stripe %d uncorrectable (need %d good columns, have %d)", stripeIdx, a.disks-2, good)
		}
		// Prefer P when it and all other data columns survive: want =
		// P XOR others. Fall back to the RS equation over Q.
		pOK := cols[a.dataDisks] != nil
		for c := 0; c < a.dataDisks; c++ {
			if c != wantData && cols[c] == nil {
				pOK = false
			}
		}
		if pOK {
			copy(p, cols[a.dataDisks])
			for c := 0; c < a.dataDisks; c++ {
				if c != wantData {
					xorInto(p, cols[c])
				}
			}
			return nil
		}
		return a.reconstructRaid6(p, cols, wantData)
	}
	return errors.New("raid: unsupported level")
}

// reconstructRaid6 solves for one missing data column using the Q
// (Reed-Solomon) equation when P alone is insufficient. With exactly
// one missing data column and Q intact:
//
//	Q = Σ α^c · D[c]  ⇒  D[want] = α^(-want) · (Q ⊕ Σ_{c≠want} α^c · D[c])
//
// If Q is also damaged the stripe is uncorrectable with one equation.
func (a *Array) reconstructRaid6(p []byte, cols [][]byte, wantData int) error {
	q := cols[a.dataDisks+1]
	if q == nil {
		return fmt.Errorf("raid: stripe uncorrectable: data column %d and Q both damaged", wantData)
	}
	// Accumulate Σ α^c · D[c] over the surviving data columns.
	acc := make([]byte, len(p))
	for c := 0; c < a.dataDisks; c++ {
		if c == wantData || cols[c] == nil {
			continue
		}
		a.gf.mulXor(acc, cols[c], a.gf.Pow(c))
	}
	// want = α^(-want) · (Q ⊕ acc)
	for i := range p {
		p[i] = q[i] ^ acc[i]
	}
	a.gf.mulConst(p, a.gf.Pow(a.gf.gfDeg-wantData)) // α^(-want) = α^(255-want)
	return nil
}

func xorInto(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}
