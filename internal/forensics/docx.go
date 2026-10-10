package forensics

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"
)

// WriteDOCX renders the report as a minimal Office Open XML document
// (a .docx is a ZIP container of XML parts). The package carries only
// the parts Word/LibreOffice need to open the file: [Content_Types],
// the package relationship, the document part and the document
// relationships. No styles part is required — Word synthesises the
// defaults — which keeps the generator dependency-free and the output
// maximally portable.
func WriteDOCX(w io.Writer, c *Case, generatedAt time.Time) error {
	return writeDOCX(w, c, generatedAt, nil)
}

// WriteDOCXBates is WriteDOCX with Bates numbering applied.
func WriteDOCXBates(w io.Writer, c *Case, generatedAt time.Time, opts BatesOptions) error {
	return writeDOCX(w, c, generatedAt, &opts)
}

func writeDOCX(w io.Writer, c *Case, generatedAt time.Time, bates *BatesOptions) error {
	doc, err := BuildReport(c, generatedAt)
	if err != nil {
		return err
	}
	if bates != nil {
		ApplyBates(&doc, *bates)
	}

	var document bytes.Buffer
	document.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n")
	document.WriteString(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` + "\n")
	document.WriteString("<w:body>\n")

	para := func(text string, bold bool) {
		document.WriteString("<w:p>")
		if text != "" {
			document.WriteString("<w:r>")
			if bold {
				document.WriteString("<w:rPr><w:b/></w:rPr>")
			}
			document.WriteString("<w:t xml:space=\"preserve\">")
			document.WriteString(xmlEscape(text))
			document.WriteString("</w:t></w:r>")
		}
		document.WriteString("</w:p>\n")
	}
	heading := func(text string) { para(text, true) }

	heading("GoHex Forensic Case Report")
	para(fmt.Sprintf("Report format: %s", doc.ReportFormat), false)
	para(fmt.Sprintf("Generated: %s", doc.GeneratedAt.Format(time.RFC3339)), false)
	para(fmt.Sprintf("Tool: %s %s (%s)", doc.Tool.Name, doc.Tool.Version, doc.Tool.GOOS), false)
	para(fmt.Sprintf("Case checksum (SHA-256): %s", doc.Checksum), false)
	if bates != nil && bates.Valid() {
		para(fmt.Sprintf("Bates numbering: %s … (%s)", bates.Format(bates.Start), bates.Prefix), false)
	}
	para("", false)

	heading("Case")
	para(fmt.Sprintf("ID: %s", doc.Case.ID), false)
	para(fmt.Sprintf("Name: %s", doc.Case.Name), false)
	para(fmt.Sprintf("Examiner: %s", orDash(doc.Case.Examiner)), false)
	para(fmt.Sprintf("Description: %s", orDash(doc.Case.Description)), false)
	para(fmt.Sprintf("Created: %s", fmtTime(doc.Case.CreatedAt)), false)
	para(fmt.Sprintf("Modified: %s", fmtTime(doc.Case.ModifiedAt)), false)
	para("", false)

	heading(fmt.Sprintf("Evidence (%d)", len(doc.Evidence)))
	if len(doc.Evidence) == 0 {
		para("(none)", false)
	}
	for _, e := range doc.Evidence {
		head := fmt.Sprintf("[%s] %s", e.Kind, e.Path)
		if e.BatesID != "" {
			head = fmt.Sprintf("%s  [%s] %s", e.BatesID, e.Kind, e.Path)
		}
		para(head, false)
		para(fmt.Sprintf("    size %d  sha256 %s", e.Size, e.SHA256), false)
		para(fmt.Sprintf("    added %s  %s", fmtTime(e.AddedAt), orDash(e.Note)), false)
	}
	para("", false)

	heading(fmt.Sprintf("Findings (%d)", len(doc.Findings)))
	if len(doc.Findings) == 0 {
		para("(none)", false)
	}
	for _, f := range doc.Findings {
		para(fmt.Sprintf("[%s] %s", strings.ToUpper(f.Severity), f.Title), false)
		para(fmt.Sprintf("    %s  created %s", orDash(f.Detail), fmtTime(f.CreatedAt)), false)
		if f.EvidenceID != "" {
			para(fmt.Sprintf("    evidence: %s", f.EvidenceID), false)
		}
	}
	para("", false)

	heading(fmt.Sprintf("Timeline (%d)", len(doc.Timeline)))
	if len(doc.Timeline) == 0 {
		para("(none)", false)
	}
	for _, ev := range doc.Timeline {
		if ev.BatesID != "" {
			para(fmt.Sprintf("%s  %s  %s  %s", ev.BatesID, fmtTime(ev.Time), ev.Kind, ev.Summary), false)
			continue
		}
		para(fmt.Sprintf("%s  %s  %s", fmtTime(ev.Time), ev.Kind, ev.Summary), false)
	}

	// Section properties: A4 page, default margins.
	document.WriteString(`<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>` +
		`<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>` + "\n")
	document.WriteString("</w:body></w:document>\n")

	contentTypes := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
`
	pkgRels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
`
	docRels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
`

	zw := zip.NewWriter(w)
	add := func(name, body string) error {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = io.WriteString(f, body)
		return err
	}
	if err := add("[Content_Types].xml", contentTypes); err != nil {
		return err
	}
	if err := add("_rels/.rels", pkgRels); err != nil {
		return err
	}
	if err := add("word/_rels/document.xml.rels", docRels); err != nil {
		return err
	}
	if err := add("word/document.xml", document.String()); err != nil {
		return err
	}
	return zw.Close()
}

// xmlEscape escapes the five XML special characters; everything else is
// already safe because the report is plain text.
func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}
