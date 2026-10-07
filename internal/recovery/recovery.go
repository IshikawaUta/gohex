// Package recovery implements signature-based file carving: it locates
// embedded files inside a larger read-only byte source by their magic numbers,
// determines each candidate's extent from a footer or an embedded length
// field, and reports offset/length pairs that callers can export.
//
// The scanner is single-pass and never writes to the source. It walks the
// source in fixed windows, keeps an ordered queue of candidates whose footer
// has not been seen yet, and emits results strictly in ascending offset order
// so a header sitting inside an already-carved object is never reported twice.
//
// Candidates are only reported when their extent is actually known:
// footer-terminated objects must find their footer inside the allowed region
// (unless Options.AllowTruncated is set), and header-only formats must carry a
// length field the parser understands. Formats with neither are deliberately
// not registered — reporting an object whose size was guessed would be worse
// than omitting it.
package recovery

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Stream is the read-only random-access input the carver works on.
// core.Source and hex.Stream both satisfy it.
type Stream interface {
	io.ReaderAt
	Size() int64
}

const (
	// scanWindow is the streaming window size for the header/footer scan. It
	// matches hex.searchWindow so both engines read evidence the same way.
	scanWindow = 4 << 20

	// defaultMaxSize bounds one carved object when neither the spec nor
	// Options.MaxSize sets a smaller limit.
	defaultMaxSize = 1 << 30

	// maxPending bounds how many unresolved candidates may be tracked at once,
	// so a region dense in false-positive headers cannot exhaust memory. The
	// earliest candidates win because they are the most likely to be real.
	maxPending = 8192

	// copyChunk is the streaming size used by Extract.
	copyChunk = 256 << 10
)

// LengthFunc reports the total length of the object starting at start.
// truncated is true when the object provably continues past the end of the
// source. ok is false when the bytes at start do not carry a usable length —
// this doubles as structural validation for weak headers such as "BM".
type LengthFunc func(s Stream, start int64) (length int64, truncated bool, ok bool)

// ValidateFunc is a cheap structural check applied once per header hit, before
// a candidate is queued. It rejects false positives from headers too short to
// be trusted on their own (for example "GIF8").
type ValidateFunc func(s Stream, start int64) bool

// FooterEnd, when set, returns where the object really ends once its footer
// has been located at footerStart. It must return an offset in (footerStart,
// limit]; returning anything else keeps the plain footer length. Formats whose
// footer carries a length field (the ZIP end-of-central-directory record) need
// this to avoid truncating the record itself.
type FooterEndFunc func(s Stream, footerStart, limit int64) int64

// Spec describes one carveable file type. A spec must carry a Header and at
// least one of Footer or Length — otherwise the extent would have to be guessed.
type Spec struct {
	// Name is the stable identifier used by Options.Types and Carved.Type.
	Name string
	// Display is the human-readable type shown in the UI.
	Display string
	// Ext is the suggested extension including the leading dot.
	Ext string

	// Header is the magic number searched for. The candidate's start offset is
	// HeaderOffset+StartDelta, which lets formats whose magic number is not at
	// offset 0 (MP4's "ftyp") participate in the same scan.
	Header []byte
	// StartDelta shifts the reported start relative to the header hit. It is
	// never positive in the shipped specs.
	StartDelta int

	// Footer, when set, terminates the object; the extent ends after it.
	Footer []byte
	// FooterEnd refines the extent once Footer matched.
	FooterEnd FooterEndFunc

	// Length, when set, derives the extent from the object itself. It is the
	// only way header-only formats (BMP, RIFF, MP4) can be carved safely.
	Length LengthFunc
	// Validate runs before a candidate is queued.
	Validate ValidateFunc

	// MinSize discards implausibly small results.
	MinSize int64
	// MaxSize caps how far the footer may be from the header. Zero means the
	// per-call Options.MaxSize applies instead.
	MaxSize int64
}

// SpecInfo is the UI-facing description of a registered type.
type SpecInfo struct {
	Name    string `json:"name"`
	Display string `json:"display"`
	Ext     string `json:"ext"`
	// Extent describes how the size is determined: "footer" or "length".
	Extent string `json:"extent"`
}

// Carved is one recovered object.
type Carved struct {
	Index     int    `json:"index"`
	Type      string `json:"type"`
	Display   string `json:"display"`
	Ext       string `json:"ext"`
	Offset    int64  `json:"offset"`
	Length    int64  `json:"length"`
	HeaderLen int64  `json:"headerLen"`
	// Truncated marks an object whose declared or region-bounded extent runs
	// past the end of the scanned range.
	Truncated bool `json:"truncated"`
}

// Options configures a carve run.
type Options struct {
	// From and To bound the scanned range; both default to the whole source.
	From, To int64
	// Types limits the run to the named specs; empty means every registered
	// type. Unknown names are an error rather than a silent no-op.
	Types []string
	// Max caps the number of results (0 = unlimited).
	Max int
	// MaxSize caps a single object when its spec does not set MaxSize.
	MaxSize int64
	// AllowTruncated reports footer-terminated candidates whose footer lies
	// beyond the scanned range instead of discarding them. It is off by
	// default because such candidates are frequently false positives.
	AllowTruncated bool
	// Progress, when set, is called with (scanned, total) after each window.
	Progress func(done, total int64)
}

// pending is a queued candidate awaiting its extent.
type pending struct {
	spec      *Spec
	start     int64
	seek      int64 // footer may start at or after this offset
	limit     int64 // exclusive: the object may not end past this
	truncOK   bool  // limit reached the scanned range end
	end       int64 // valid once resolved
	truncated bool
	resolved  bool
	exhausted bool // allowed region fully scanned without a footer
}

// carver holds the state of one Carve call.
type carver struct {
	s        Stream
	opts     Options
	specs    []*Spec
	maxSize  int64
	from     int64
	to       int64
	out      []Carved
	pend     []*pending
	nextFrom int64
	full     bool
}

// rawHit is a header occurrence found in the current window.
type rawHit struct {
	spec  *Spec
	start int64
}

// Carve scans the configured range of s and returns the objects it can bound,
// in ascending offset order. Results found before a read error are returned
// together with that error so callers can salvage partial work.
func Carve(s Stream, opts Options) ([]Carved, error) {
	if s == nil {
		return nil, errors.New("recovery: nil stream")
	}
	size := s.Size()
	if size <= 0 {
		return nil, nil
	}
	from, to := opts.From, opts.To
	if from < 0 {
		from = 0
	}
	if to <= 0 || to > size {
		to = size
	}
	if from >= to {
		return nil, nil
	}
	specs, err := selectSpecs(opts.Types)
	if err != nil {
		return nil, err
	}
	maxSize := opts.MaxSize
	if maxSize <= 0 {
		maxSize = defaultMaxSize
	}
	c := &carver{
		s: s, opts: opts, specs: specs, maxSize: maxSize,
		from: from, to: to, nextFrom: from,
	}
	if err := c.run(); err != nil {
		return c.out, err
	}
	return c.out, nil
}

// run performs the single windowed pass over the source.
func (c *carver) run() error {
	ov := overlapLen(c.specs)
	total := c.to - c.from
	for seg := c.from; seg < c.to && !c.full; {
		segEnd := seg + scanWindow
		if segEnd > c.to {
			segEnd = c.to
		}
		readEnd := segEnd + int64(ov)
		if readEnd > c.s.Size() {
			readEnd = c.s.Size()
		}
		buf := make([]byte, readEnd-seg)
		if err := readFullAt(c.s, buf, seg); err != nil {
			return fmt.Errorf("recovery: read at %#x: %w", seg, err)
		}
		pos := footerPositions(c.specs, buf, seg)
		for _, h := range findHits(c.specs, buf, seg, segEnd, c.nextFrom) {
			c.add(h.spec, h.start)
		}
		sort.SliceStable(c.pend, func(i, j int) bool { return c.pend[i].start < c.pend[j].start })
		for _, p := range c.pend {
			c.resolve(p, seg, readEnd, pos)
		}
		c.drain()
		if len(c.pend) > maxPending {
			c.pend = c.pend[:maxPending]
		}
		seg = segEnd
		if c.opts.Progress != nil {
			c.opts.Progress(seg-c.from, total)
		}
	}
	c.drain()
	return nil
}

// resolve advances one queued candidate against the current window.
func (c *carver) resolve(p *pending, seg, readEnd int64, pos map[*Spec][]int64) {
	if p.resolved || p.exhausted || p.spec.Footer == nil {
		return
	}
	flen := int64(len(p.spec.Footer))
	from := p.seek
	if from < seg {
		from = seg
	}
	if at := firstAt(pos[p.spec], from, flen, p.limit); at >= 0 {
		end := at + flen
		if p.spec.FooterEnd != nil {
			if e := p.spec.FooterEnd(c.s, at, p.limit); e > p.limit {
				// The footer declares more data than the scanned range holds.
				end, p.truncated = p.limit, true
			} else if e > at {
				end = e
			}
		}
		if end > p.limit {
			end = p.limit
		}
		p.end, p.resolved = end, true
		return
	}
	if p.limit <= readEnd {
		p.exhausted = true
	}
}

// add queues a candidate, resolving it immediately when its extent is already
// known (length-based formats) or when the footer sits in the current window.
func (c *carver) add(sp *Spec, start int64) {
	if start < 0 || start < c.nextFrom {
		return
	}
	if sp.Validate != nil && !sp.Validate(c.s, start) {
		return
	}
	hl := headerLen(sp)
	limit := c.to
	if sp.MaxSize > 0 && start+sp.MaxSize < limit {
		limit = start + sp.MaxSize
	}
	if start+c.maxSize < limit {
		limit = start + c.maxSize
	}
	if limit < start+hl+1 {
		return
	}
	p := &pending{
		spec: sp, start: start, seek: start + hl, limit: limit,
		truncOK: limit >= c.to,
	}
	if sp.Footer == nil {
		if sp.Length == nil {
			return // no footer and no length field: extent would be a guess
		}
		length, trunc, ok := sp.Length(c.s, start)
		if !ok || length <= 0 {
			return
		}
		if length > limit-start {
			if !p.truncOK {
				return
			}
			length, trunc = limit-start, true
		}
		if length < sp.MinSize {
			return
		}
		p.end, p.truncated, p.resolved = start+length, trunc, true
	}
	c.pend = append(c.pend, p)
}

// drain emits queued candidates in offset order, stopping at the first one
// that still needs data from a later window.
func (c *carver) drain() {
	for len(c.pend) > 0 && !c.full {
		p := c.pend[0]
		if p.start < c.nextFrom { // nested inside an already-carved object
			c.pend = c.pend[1:]
			continue
		}
		switch {
		case p.resolved:
			c.emit(p, p.end-p.start, p.truncated)
			c.pend = c.pend[1:]
		case p.exhausted:
			if c.opts.AllowTruncated && p.truncOK {
				if length := p.limit - p.start; length >= p.spec.MinSize {
					c.emit(p, length, true)
				}
			}
			c.pend = c.pend[1:]
		default:
			return // head is waiting for a later window
		}
	}
}

func (c *carver) emit(p *pending, length int64, truncated bool) {
	if c.opts.Max > 0 && len(c.out) >= c.opts.Max {
		c.full = true
		return
	}
	c.out = append(c.out, Carved{
		Index:     len(c.out),
		Type:      p.spec.Name,
		Display:   p.spec.Display,
		Ext:       p.spec.Ext,
		Offset:    p.start,
		Length:    length,
		HeaderLen: headerLen(p.spec),
		Truncated: truncated,
	})
	c.nextFrom = p.start + length
}

// headerLen is the distance from the object start to the end of its magic
// number: the header plus any bytes the start offset is shifted back over.
func headerLen(sp *Spec) int64 {
	n := int64(len(sp.Header)) - int64(sp.StartDelta)
	if n < 1 {
		return 1
	}
	return n
}

// overlapLen is how many bytes past the window end must be read so a header or
// footer straddling the boundary is still matched by exactly one window.
func overlapLen(specs []*Spec) int {
	max := 1
	for _, sp := range specs {
		if n := len(sp.Header); n > max {
			max = n
		}
		if n := len(sp.Footer); n > max {
			max = n
		}
	}
	return max - 1
}

// findHits returns every header occurrence starting in [seg, segEnd), shifted
// by the spec's StartDelta and filtered against nextFrom.
func findHits(specs []*Spec, buf []byte, seg, segEnd, nextFrom int64) []rawHit {
	var hits []rawHit
	for _, sp := range specs {
		if len(sp.Header) == 0 {
			continue
		}
		for i := 0; i+len(sp.Header) <= len(buf); {
			j := bytes.Index(buf[i:], sp.Header)
			if j < 0 {
				break
			}
			// bytes.Index reports a position inside buf[i:], so i must be
			// added back — otherwise every hit after the first carries an
			// offset relative to the previous one.
			if abs := seg + int64(i+j) + int64(sp.StartDelta); abs < segEnd && abs >= nextFrom {
				hits = append(hits, rawHit{spec: sp, start: abs})
			}
			i += j + 1
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].start < hits[j].start })
	return hits
}

// footerPositions collects every footer occurrence in the window, keyed by
// spec, so all queued candidates can be matched by binary search instead of
// re-scanning the bytes once per candidate.
func footerPositions(specs []*Spec, buf []byte, base int64) map[*Spec][]int64 {
	var out map[*Spec][]int64
	for _, sp := range specs {
		if len(sp.Footer) == 0 {
			continue
		}
		var list []int64
		for i := 0; i+len(sp.Footer) <= len(buf); {
			j := bytes.Index(buf[i:], sp.Footer)
			if j < 0 {
				break
			}
			list = append(list, base+int64(i+j))
			i += j + 1
		}
		if len(list) > 0 {
			if out == nil {
				out = make(map[*Spec][]int64, 1)
			}
			out[sp] = list
		}
	}
	return out
}

// firstAt finds the first footer occurrence at or after from whose end stays
// inside limit, or -1.
func firstAt(list []int64, from, flen, limit int64) int64 {
	i := sort.Search(len(list), func(i int) bool { return list[i] >= from })
	if i >= len(list) {
		return -1
	}
	if list[i]+flen > limit {
		return -1 // occurrences are ascending, so none of them fits
	}
	return list[i]
}

// readFullAt fills p at off, treating a short read as an error.
func readFullAt(s Stream, p []byte, off int64) error {
	total := 0
	for total < len(p) {
		n, err := s.ReadAt(p[total:], off+int64(total))
		total += n
		if err != nil {
			if errors.Is(err, io.EOF) && total == len(p) {
				return nil
			}
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

// selectSpecs resolves Options.Types against the registry. An empty list means
// every registered spec; an unknown name is an error.
func selectSpecs(names []string) ([]*Spec, error) {
	if len(names) == 0 {
		return append([]*Spec(nil), registry...), nil
	}
	out := make([]*Spec, 0, len(names))
	seen := make(map[*Spec]bool, len(names))
	for _, n := range names {
		sp, ok := specByName[strings.ToLower(strings.TrimSpace(n))]
		if !ok {
			return nil, fmt.Errorf("recovery: unknown file type %q", n)
		}
		if !seen[sp] {
			seen[sp] = true
			out = append(out, sp)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("recovery: no file types selected")
	}
	return out, nil
}

// Types lists the registered carveable types for the UI.
func Types() []SpecInfo {
	out := make([]SpecInfo, 0, len(registry))
	for _, sp := range registry {
		extent := "length"
		if sp.Footer != nil {
			extent = "footer"
		}
		out = append(out, SpecInfo{
			Name: sp.Name, Display: sp.Display, Ext: sp.Ext, Extent: extent,
		})
	}
	return out
}

// HasType reports whether name is a registered file type.
func HasType(name string) bool {
	_, ok := specByName[strings.ToLower(strings.TrimSpace(name))]
	return ok
}
