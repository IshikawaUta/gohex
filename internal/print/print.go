// Package print renders hex-grid views — offset, hex bytes, ASCII
// gutter — into PDF and PNG exhibits. It is the paper counterpart of
// the on-screen hex view: an examiner hands the printed grid to a
// court or a colleague, and the rendering must be byte-for-byte
// reproducible from the same data.
package print

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"strings"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

// Width is the number of bytes per line in the classic hex grid.
const Width = 16

// MaxLines bounds a single render. The PNG format caps images at
// 65535 px per side and a 7x13 face makes each line 13 px tall, so
// 4000 lines (~52k px) is the honest ceiling for one sheet; the PDF
// paginates, but an exhibit that thick belongs in the report, not a
// printout.
const MaxLines = 4000

// Lines renders data as the classic hex grid: zero-padded offset,
// space-separated hex bytes grouped every 8, and an ASCII gutter
// with non-printables as dots. base is the file offset of data[0].
func Lines(data []byte, base int64) []string {
	out := make([]string, 0, (len(data)+Width-1)/Width)
	for i := 0; i < len(data); i += Width {
		chunk := data[i:min(i+Width, len(data))]
		var hex strings.Builder
		for j := 0; j < Width; j++ {
			if j%8 == 0 {
				hex.WriteByte(' ')
			}
			if j < len(chunk) {
				hex.WriteString(fmt.Sprintf("%02x ", chunk[j]))
			} else {
				hex.WriteString("   ")
			}
		}
		var ascii strings.Builder
		for _, b := range chunk {
			if b >= 0x20 && b <= 0x7e {
				ascii.WriteByte(b)
			} else {
				ascii.WriteByte('.')
			}
		}
		out = append(out, fmt.Sprintf("%08X  %s |%s|", base+int64(i), hex.String(), ascii.String()))
	}
	return out
}

// PDF renders title plus the grid lines as a paginated PDF 1.4
// document using only the base-14 Courier font (fixed pitch — the
// columns must align). No dependencies beyond the standard library.
func PDF(w io.Writer, title string, lines []string) error {
	pw := newPDFWriter()
	pw.line(asciiTitle(title), 14, 0)
	pw.line(fmt.Sprintf("GoHex hex-grid export — %d line(s)", len(lines)), 9, 12)
	for _, ln := range lines {
		pw.line(ln, 8, 0)
	}
	return pw.write(w)
}

// asciiTitle strips anything the standard font cannot encode.
func asciiTitle(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r <= 126 {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	t := strings.TrimSpace(b.String())
	if t == "" {
		return "GoHex hex-grid export"
	}
	return t
}

// PNG renders title plus the grid lines onto a white sheet with the
// embedded 7x13 bitmap face — no font files, no system dependency,
// identical output on every platform.
func PNG(w io.Writer, title string, lines []string) error {
	const (
		margin = 16
		lineH  = 13
		charW  = 7
		titleH = 28
	)
	n := len(lines)
	if n == 0 {
		lines = []string{"(empty range)"}
		n = 1
	}
	maxLen := len(asciiTitle(title))
	for _, ln := range lines {
		if len(ln) > maxLen {
			maxLen = len(ln)
		}
	}
	img := image.NewRGBA(image.Rect(0, 0, margin*2+maxLen*charW, margin*2+titleH+n*lineH))
	// White sheet, black ink — printable as-is.
	white := image.NewUniform(color.RGBA{255, 255, 255, 255})
	for x := img.Bounds().Min.X; x < img.Bounds().Max.X; x++ {
		for y := img.Bounds().Min.Y; y < img.Bounds().Max.Y; y++ {
			img.Set(x, y, white)
		}
	}

	d := font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(color.RGBA{0, 0, 0, 255}),
		Face: basicfont.Face7x13,
	}
	ink := fixed.I(margin)
	d.Dot.Y = fixed.I(margin + 10)
	d.Dot.X = ink
	d.DrawString(asciiTitle(title))

	d.Dot.Y = fixed.I(margin + titleH)
	for _, ln := range lines {
		d.Dot.X = ink
		d.DrawString(ln)
		d.Dot.Y += fixed.I(lineH)
	}
	return png.Encode(w, img)
}

// ---- minimal PDF writer (same durable shape as internal/forensics) ----

type pdfPage struct {
	lines []pdfLine
}

type pdfLine struct {
	text string
	size float64
	gap  float64
}

type pdfWriter struct {
	pages   []*pdfPage
	current *pdfPage
}

func newPDFWriter() *pdfWriter {
	w := &pdfWriter{}
	w.newPage()
	return w
}

func (w *pdfWriter) newPage() {
	w.current = &pdfPage{}
	w.pages = append(w.pages, w.current)
}

func (w *pdfWriter) line(text string, size, gap float64) {
	// Hex-grid lines are exactly 75 chars; the title is short. Wrapping
	// at 92 keeps any caller-supplied text on the page.
	const maxChars = 92
	for _, chunk := range wrapText(text, maxChars) {
		if len(w.current.lines) >= 58 { // fits A4 at 8pt/13pt leading
			w.newPage()
		}
		w.current.lines = append(w.current.lines, pdfLine{text: chunk, size: size, gap: gap})
		gap = 0
	}
}

func wrapText(s string, max int) []string {
	if len(s) <= max {
		return []string{s}
	}
	var out []string
	for len(s) > max {
		out = append(out, s[:max])
		s = s[max:]
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}

func pdfEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '(' || r == ')' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 32 || r > 126:
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// write emits PDF 1.4 with Courier as the fixed-pitch font.
func (w *pdfWriter) write(out io.Writer) error {
	return writeClean(out, w.pages)
}

// writeClean serialises the document in one pass: 1 catalog, 2 pages,
// then per page (page object, content stream), then the font — correct
// object numbering and xref in a single sweep, because patching PDF
// offsets in place is how PDF bugs are born.
func writeClean(out io.Writer, pages []*pdfPage) error {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	offsets := make([]int, 0, 3+2*len(pages)+1)

	put := func(body string) {
		offsets = append(offsets, buf.Len())
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", len(offsets), body)
	}

	fontObj := 3 + 2*len(pages)
	kids := make([]string, len(pages))
	for i := range pages {
		kids[i] = fmt.Sprintf("%d 0 R", 3+2*i)
	}
	put("<< /Type /Catalog /Pages 2 0 R >>")
	put(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages)))

	for i, page := range pages {
		contentObj := 4 + 2*i
		put(fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents %d 0 R /Resources << /Font << /F1 %d 0 R >> >> >>",
			contentObj, fontObj))

		var content bytes.Buffer
		content.WriteString("BT\n")
		y := 800.0
		for _, ln := range page.lines {
			y -= ln.gap + ln.size
			if y < 40 {
				break // safety: never draw into the footer margin
			}
			fmt.Fprintf(&content, "/F1 %.1f Tf 1 0 0 1 48 %.1f Tm (%s) Tj\n",
				ln.size, y, pdfEscape(ln.text))
		}
		content.WriteString("ET\n")
		put(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", content.Len(), content.String()))
	}
	put("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")

	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", len(offsets)+1)
	buf.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, xref)
	_, err := out.Write(buf.Bytes())
	return err
}
