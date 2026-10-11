package forensics

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleCase(t *testing.T) *Case {
	t.Helper()
	c, err := New("Operation Nightfall", "A. Analyst", "laptop seized 2024-03-04")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddEvidence(Evidence{
		Path: "/evidence/nightfall.dd", Kind: KindImage, Size: 2 << 30,
		SHA256: strings.Repeat("ab", 32),
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.AddFinding(Finding{
		Title: "Browser history shows staging host", Severity: SeverityHigh,
		Detail: "example.test contacted at 03:04 UTC.", EvidenceID: "e-001",
	}); err != nil {
		t.Fatal(err)
	}
	for _, e := range []Event{
		{
			Time: time.Date(2024, 3, 4, 3, 5, 0, 0, time.UTC), Source: "browser:Chrome",
			Kind: EventVisit, Summary: "https://example.test/stage", EvidenceID: "e-001",
		},
		{
			Time: time.Date(2024, 3, 4, 2, 0, 0, 0, time.UTC), Source: "carve",
			Kind: EventCarve, Summary: "recovered photo.jpg",
		},
		{Kind: EventManual, Summary: "examiner note, time unknown"},
	} {
		if err := c.AddEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func TestBuildReport(t *testing.T) {
	c := sampleCase(t)
	when := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	doc, err := BuildReport(c, when)
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}
	if doc.ReportFormat != ReportFormat {
		t.Errorf("reportFormat = %q", doc.ReportFormat)
	}
	if !doc.GeneratedAt.Equal(when) {
		t.Errorf("generatedAt = %v, want %v", doc.GeneratedAt, when)
	}
	if doc.Case.Name != "Operation Nightfall" || doc.Case.ID != c.ID {
		t.Errorf("case = %+v", doc.Case)
	}
	if len(doc.Evidence) != 1 || len(doc.Findings) != 1 || len(doc.Timeline) != 3 {
		t.Errorf("counts = %d/%d/%d", len(doc.Evidence), len(doc.Findings), len(doc.Timeline))
	}
	want, err := CaseChecksum(c)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Checksum != want {
		t.Errorf("checksum = %s, want %s", doc.Checksum, want)
	}
	if len(doc.Checksum) != 64 {
		t.Errorf("checksum length = %d", len(doc.Checksum))
	}
	// The timeline must be sorted: earliest first, unknown time last.
	if !doc.Timeline[0].Time.Before(doc.Timeline[1].Time) {
		t.Errorf("timeline not sorted: %v then %v", doc.Timeline[0].Time, doc.Timeline[1].Time)
	}
	if !doc.Timeline[len(doc.Timeline)-1].Time.IsZero() {
		t.Error("event with no time should come last")
	}
	// The document must be a rendering, not a mutation.
	if len(c.Events) != 3 {
		t.Error("BuildReport changed the case")
	}

	if _, err := BuildReport(nil, when); err == nil {
		t.Error("built a report from no case")
	}
	// A zero time means "now".
	doc, err = BuildReport(c, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if doc.GeneratedAt.IsZero() {
		t.Error("generatedAt not defaulted")
	}
	// The tool line is filled in even for a case that never carried one.
	if doc.Tool.Name != "GoHex" {
		t.Errorf("tool = %+v", doc.Tool)
	}
}

func TestCaseChecksumIsStableAndSensitive(t *testing.T) {
	c := sampleCase(t)
	a, err := CaseChecksum(c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CaseChecksum(c)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("checksum not stable: %s vs %s", a, b)
	}
	c.Name = "Renamed"
	d, err := CaseChecksum(c)
	if err != nil {
		t.Fatal(err)
	}
	if d == a {
		t.Error("checksum did not change when the case changed")
	}
	// Pretty-printing must not matter: the checksum is over the compact form.
	c.Name = "Operation Nightfall"
	pretty, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var round Case
	if err := json.Unmarshal(pretty, &round); err != nil {
		t.Fatal(err)
	}
	e, err := CaseChecksum(&round)
	if err != nil {
		t.Fatal(err)
	}
	if e != a {
		t.Errorf("checksum changed through a pretty-print round trip: %s vs %s", e, a)
	}
}

func TestWriteJSON(t *testing.T) {
	c := sampleCase(t)
	var buf bytes.Buffer
	if err := WriteJSON(&buf, c, time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	out := buf.Bytes()
	if !bytes.HasSuffix(out, []byte("\n")) {
		t.Error("report JSON is not newline terminated")
	}
	var doc ReportDocument
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if doc.Case.Name != c.Name || len(doc.Timeline) != 3 {
		t.Errorf("decoded report = %+v", doc)
	}
	if doc.Checksum == "" || doc.GeneratedAt.IsZero() {
		t.Errorf("missing integrity fields: %+v", doc)
	}
	// The JSON view and the in-memory case must agree on the order of events.
	if doc.Timeline[0].Summary != "recovered photo.jpg" {
		t.Errorf("first event = %q", doc.Timeline[0].Summary)
	}

	if err := WriteJSON(&buf, nil, time.Now()); err == nil {
		t.Error("wrote a report from no case")
	}
}

func TestApplyBates(t *testing.T) {
	c := sampleCase(t)
	doc, err := BuildReport(c, time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	opts := BatesOptions{Prefix: "EXH", Start: 1, Width: 4}
	if !opts.Valid() {
		t.Fatal("EXH/1/4 should be valid")
	}
	if got := opts.Format(7); got != "EXH-0007" {
		t.Errorf("Format(7) = %q", got)
	}
	if (BatesOptions{}).Valid() || (BatesOptions{Prefix: "X", Width: 99}).Valid() {
		t.Error("invalid options accepted")
	}

	ApplyBates(&doc, opts)
	if len(doc.Evidence) == 0 || doc.Evidence[0].BatesID != "EXH-0001" {
		t.Errorf("first evidence BatesID = %q", doc.Evidence[0].BatesID)
	}
	if doc.Timeline[0].BatesID != "EXH-0002" || doc.Timeline[2].BatesID != "EXH-0004" {
		t.Errorf("timeline BatesIDs = %q..%q", doc.Timeline[0].BatesID, doc.Timeline[2].BatesID)
	}
	// The case file must stay unnumbered: only the report copy is stamped.
	if c.Evidence[0].BatesID != "" || c.Events[0].BatesID != "" {
		t.Error("ApplyBates mutated the case file")
	}

	// Zero-value options are a no-op, not a panic.
	ApplyBates(&doc, BatesOptions{})
	if doc.Evidence[0].BatesID == "" {
		t.Error("valid numbering was clobbered by a no-op ApplyBates")
	}
}

func TestWriteBatesVariants(t *testing.T) {
	c := sampleCase(t)
	gen := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	opts := BatesOptions{Prefix: "CASE-A", Start: 100, Width: 6}

	var buf bytes.Buffer
	if err := WriteJSONBates(&buf, c, gen, opts); err != nil {
		t.Fatalf("WriteJSONBates: %v", err)
	}
	var doc ReportDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("bates JSON invalid: %v", err)
	}
	if doc.Evidence[0].BatesID != "CASE-A-000100" {
		t.Errorf("JSON evidence BatesID = %q", doc.Evidence[0].BatesID)
	}
	if doc.Timeline[0].BatesID != "CASE-A-000101" {
		t.Errorf("JSON timeline BatesID = %q", doc.Timeline[0].BatesID)
	}

	buf.Reset()
	if err := WritePDFBates(&buf, c, gen, opts); err != nil {
		t.Fatalf("WritePDFBates: %v", err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF")) {
		t.Error("PDFBates output is not a PDF")
	}
	if !bytes.Contains(buf.Bytes(), []byte("CASE-A-000100")) {
		t.Error("PDF is missing the Bates identifier")
	}

	buf.Reset()
	if err := WriteDOCXBates(&buf, c, gen, opts); err != nil {
		t.Fatalf("WriteDOCXBates: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("DOCX is not a zip: %v", err)
	}
	found := false
	for _, f := range zr.File {
		if f.Name != "word/document.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		found = bytes.Contains(body, []byte("CASE-A-000100"))
	}
	if !found {
		t.Error("DOCX document.xml is missing the Bates identifier")
	}
}

func TestWriteHTML(t *testing.T) {
	c := sampleCase(t)
	var buf bytes.Buffer
	when := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := WriteHTML(&buf, c, when); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := buf.String()
	for _, want := range []string{
		"<!DOCTYPE html>",
		"Operation Nightfall",
		"A. Analyst",
		"/evidence/nightfall.dd",
		"2.00 GiB",
		"https://example.test/stage",
		"recovered photo.jpg",
		"Browser history shows staging host",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report is missing %q", want)
		}
	}
	if !strings.Contains(html, strings.Repeat("ab", 32)) {
		t.Error("report is missing the evidence digest")
	}
	sum, err := CaseChecksum(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, sum) {
		t.Error("report is missing its checksum")
	}
	// Times are rendered in UTC, not the machine's zone.
	if !strings.Contains(html, "2024-03-04 03:05:00 UTC") {
		t.Error("event time not rendered in UTC")
	}
	// An unknown time is never rendered as Go's zero date.
	if strings.Contains(html, "0001-01-01") {
		t.Error("zero timestamp leaked into the report")
	}

	if err := WriteHTML(&buf, nil, when); err == nil {
		t.Error("wrote a report from no case")
	}
}

func TestReportEscapesHTML(t *testing.T) {
	c, err := New(`<script>alert("x")</script>`, "M. <b>O'Brien</b>", `</style><script>`)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, c, time.Now()); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if strings.Contains(html, "<script>alert") {
		t.Error("case name was injected into the report unescaped")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected escaped markup in the report")
	}
}

func TestReportOnEmptyCase(t *testing.T) {
	c, err := New("Empty", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, c, time.Now()); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := buf.String()
	for _, want := range []string{"No evidence recorded.", "No findings recorded.", "No events recorded."} {
		if !strings.Contains(html, want) {
			t.Errorf("empty report is missing %q", want)
		}
	}
	var js bytes.Buffer
	if err := WriteJSON(&js, c, time.Now()); err != nil {
		t.Fatal(err)
	}
	var doc ReportDocument
	if err := json.Unmarshal(js.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Evidence == nil || doc.Findings == nil || doc.Timeline == nil {
		t.Errorf("empty report must serialise empty arrays, got %+v", doc)
	}
}

func TestReportTemplateIsEmbedded(t *testing.T) {
	// The rendering must work from a temporary working directory, proving the
	// template comes from the binary and not from a relative file path.
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(wd) }()

	c, _ := New("Embedded", "", "")
	var buf bytes.Buffer
	if err := WriteHTML(&buf, c, time.Now()); err != nil {
		t.Fatalf("WriteHTML outside the package directory: %v", err)
	}
	if !strings.Contains(buf.String(), "Forensic case report") {
		t.Error("template did not render")
	}
	_ = filepath.Join(dir)
}
