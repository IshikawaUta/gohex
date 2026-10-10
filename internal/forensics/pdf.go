package forensics

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"
)

// pdfPage is one rendered page: a list of text lines drawn with the
// base-14 Helvetica font. The layout is deliberately plain — forensic
// reports must survive decades of tool churn, and a simple content
// stream plus the standard font set is the most durable shape possible.
type pdfPage struct {
	lines []pdfLine
}

type pdfLine struct {
	text string
	size float64
	gap  float64 // extra vertical space before this line
}

// pdfWriter accumulates pages and emits a complete PDF 1.4 document.
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

func (w *pdfWriter) line(text string, size float64, gap float64) {
	// Hard-wrap very long lines so they never overflow the page box.
	const maxChars = 92
	for _, chunk := range wrapText(text, maxChars) {
		// Start a new page roughly every 50 lines.
		if len(w.current.lines) >= 50 {
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
		// Break at the last space inside the window when possible.
		cut := strings.LastIndex(s[:max], " ")
		if cut <= 0 {
			cut = max
		}
		out = append(out, s[:cut])
		s = strings.TrimLeft(s[cut:], " ")
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}

// pdfEscape escapes the characters that are special inside a PDF string
// literal and strips any non-ASCII that would break the standard font's
// WinAnsi encoding (the report is ASCII-safe by construction, but a
// caller-supplied title could contain anything).
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

// WritePDF renders the report as a plain-text PDF using only the base-14
// Helvetica font, so the output opens anywhere without embedding fonts.
func WritePDF(w io.Writer, c *Case, generatedAt time.Time) error {
	doc, err := BuildReport(c, generatedAt)
	if err != nil {
		return err
	}
	pw := newPDFWriter()

	pw.line("GoHex Forensic Case Report", 18, 0)
	pw.line(fmt.Sprintf("Report format: %s", doc.ReportFormat), 10, 14)
	pw.line(fmt.Sprintf("Generated: %s", doc.GeneratedAt.Format(time.RFC3339)), 10, 4)
	pw.line(fmt.Sprintf("Tool: %s %s (%s)", doc.Tool.Name, doc.Tool.Version, doc.Tool.GOOS), 10, 4)
	pw.line(fmt.Sprintf("Case checksum (SHA-256): %s", doc.Checksum), 8, 4)
	pw.line("", 10, 10)

	pw.line("Case", 14, 8)
	pw.line(fmt.Sprintf("ID:          %s", doc.Case.ID), 10, 2)
	pw.line(fmt.Sprintf("Name:        %s", doc.Case.Name), 10, 2)
	pw.line(fmt.Sprintf("Examiner:    %s", orDash(doc.Case.Examiner)), 10, 2)
	pw.line(fmt.Sprintf("Description: %s", orDash(doc.Case.Description)), 10, 2)
	pw.line(fmt.Sprintf("Created:     %s", fmtTime(doc.Case.CreatedAt)), 10, 2)
	pw.line(fmt.Sprintf("Modified:    %s", fmtTime(doc.Case.ModifiedAt)), 10, 10)

	pw.line(fmt.Sprintf("Evidence (%d)", len(doc.Evidence)), 14, 8)
	if len(doc.Evidence) == 0 {
		pw.line("  (none)", 10, 2)
	}
	for _, e := range doc.Evidence {
		pw.line(fmt.Sprintf("  [%s] %s", e.Kind, e.Path), 10, 2)
		pw.line(fmt.Sprintf("      size %d  sha256 %s", e.Size, e.SHA256), 8, 2)
		pw.line(fmt.Sprintf("      added %s  %s", fmtTime(e.AddedAt), orDash(e.Note)), 8, 2)
	}
	pw.line("", 10, 6)

	pw.line(fmt.Sprintf("Findings (%d)", len(doc.Findings)), 14, 8)
	if len(doc.Findings) == 0 {
		pw.line("  (none)", 10, 2)
	}
	for _, f := range doc.Findings {
		pw.line(fmt.Sprintf("  [%s] %s", strings.ToUpper(f.Severity), f.Title), 10, 2)
		pw.line(fmt.Sprintf("      %s  created %s", orDash(f.Detail), fmtTime(f.CreatedAt)), 8, 2)
		if f.EvidenceID != "" {
			pw.line(fmt.Sprintf("      evidence: %s", f.EvidenceID), 8, 2)
		}
	}
	pw.line("", 10, 6)

	pw.line(fmt.Sprintf("Timeline (%d)", len(doc.Timeline)), 14, 8)
	if len(doc.Timeline) == 0 {
		pw.line("  (none)", 10, 2)
	}
	for _, ev := range doc.Timeline {
		pw.line(fmt.Sprintf("  %s  %-9s  %s", fmtTime(ev.Time), ev.Kind, ev.Summary), 9, 1)
	}

	return writePDFFile(w, pw)
}

// writePDFFile serialises the accumulated pages into a PDF 1.4 file.
//
// Object layout:
//
//	1: catalog
//	2: pages tree
//	3: page (repeated)
//	4: content stream (repeated)
//	5: font (Helvetica)
func writePDFFile(w io.Writer, pw *pdfWriter) error {
	var buf bytes.Buffer
	offsets := make([]int64, 0, 3+2*len(pw.pages))

	buf.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

	writeObj := func(id int, body string) {
		offsets = append(offsets, int64(buf.Len()))
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", id, body)
	}

	const fontID = 5
	nPages := len(pw.pages)
	// Object ids: 1 catalog, 2 pages, then per page: page obj (3+2i),
	// content obj (4+2i), font at the end.
	catalogID := 1
	pagesID := 2
	fontObjID := 3 + 2*nPages

	// Reserve the ids we know up front.
	kids := make([]string, nPages)
	for i := range kids {
		kids[i] = fmt.Sprintf("%d 0 R", 3+2*i)
	}

	writeObj(catalogID, fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", pagesID))
	writeObj(pagesID, fmt.Sprintf(
		"<< /Type /Pages /Kids [%s] /Count %d >>",
		strings.Join(kids, " "), nPages))

	for i, page := range pw.pages {
		pageID := 3 + 2*i
		contentID := 4 + 2*i
		writeObj(pageID, fmt.Sprintf(
			"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] "+
				"/Contents %d 0 R /Resources << /Font << /F1 %d 0 R >> >> >>",
			pagesID, contentID, fontObjID))

		var content bytes.Buffer
		content.WriteString("BT\n")
		y := 756.0
		for _, ln := range page.lines {
			y -= ln.gap
			fmt.Fprintf(&content, "/F1 %.1f Tf\n1 0 0 1 48 %.1f Tm\n(%s) Tj\n",
				ln.size, y, pdfEscape(ln.text))
			y -= ln.size * 1.35
		}
		content.WriteString("ET\n")

		stream := content.String()
		offsets = append(offsets, int64(buf.Len()))
		fmt.Fprintf(&buf, "%d 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n",
			contentID, len(stream), stream)
	}

	writeObj(fontObjID,
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")

	xrefPos := int64(buf.Len())
	fmt.Fprintf(&buf, "xref\n0 %d\n", fontObjID+1)
	buf.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		fontObjID+1, catalogID, xrefPos)

	_, err := w.Write(buf.Bytes())
	return err
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "not recorded"
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}
