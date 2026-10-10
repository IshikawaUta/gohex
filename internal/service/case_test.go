package service

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	stdhex "encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IshikawaUta/gohex/internal/forensics"
)

func caseAudit(t *testing.T, app *App) string {
	t.Helper()
	logged, err := os.ReadFile(app.cfg.AuditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(logged)
}

func mustOk(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustOpen(t *testing.T, state CaseState, err error) CaseState {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !state.Open || state.Case == nil {
		t.Fatalf("expected an open case, got %+v", state)
	}
	return state
}

func TestCaseStateStartsEmpty(t *testing.T) {
	app := newTestApp(t)
	if got := app.CaseState(); got.Open || got.Case != nil || got.Path != "" {
		t.Errorf("initial state = %+v, want empty", got)
	}
	if err := app.CaseClose(); err != nil {
		t.Errorf("closing nothing: %v", err)
	}
}

func TestCaseNew(t *testing.T) {
	app := newTestApp(t)

	if _, err := app.CaseNew("  ", "", ""); err == nil {
		t.Error("accepted a blank case name")
	}
	if got := app.CaseState(); got.Open {
		t.Error("a rejected case left state open")
	}

	st, err := app.CaseNew("Operation Nightfall", "A. Analyst", "laptop")
	mustOpen(t, st, err)
	if st.Case.Name != "Operation Nightfall" || st.Case.Examiner != "A. Analyst" {
		t.Errorf("case = %+v", st.Case)
	}
	if st.Case.ID == "" || st.Case.Tool.Name != "GoHex" {
		t.Errorf("case id/tool = %q / %+v", st.Case.ID, st.Case.Tool)
	}

	// A second case must not silently replace the first.
	if _, err := app.CaseNew("Another", "", ""); err == nil {
		t.Error("replaced an open case without being asked")
	}
	if app.CaseState().Case.ID != st.Case.ID {
		t.Error("the refused call changed the open case")
	}

	if err := app.CaseClose(); err != nil {
		t.Fatalf("CaseClose: %v", err)
	}
	if got := app.CaseState(); got.Open {
		t.Errorf("state after close = %+v, want empty", got)
	}
	if err := app.CaseClose(); err != nil {
		t.Errorf("second close: %v", err)
	}

	firstID := st.Case.ID
	st, err = app.CaseNew("Second", "", "")
	mustOpen(t, st, err)
	if st.Case.Name != "Second" || st.Case.ID == firstID {
		t.Errorf("second case = %+v, first = %q", st.Case, firstID)
	}
	if logged := caseAudit(t, app); !strings.Contains(logged, `"op":"new"`) || !strings.Contains(logged, `"op":"close"`) {
		t.Errorf("audit log is missing case lifecycle entries:\n%s", logged)
	}
}

func TestCaseSetMeta(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.CaseSetMeta("x", "", ""); !errors.Is(err, errNoCase) {
		t.Errorf("with no case open: %v", err)
	}
	_, err := app.CaseNew("first", "someone", "d")
	mustOk(t, err)
	st, err := app.CaseSetMeta("renamed", " B ", "note")
	mustOpen(t, st, err)
	if st.Case.Name != "renamed" || st.Case.Examiner != "B" || st.Case.Description != "note" {
		t.Errorf("meta = %+v", st.Case)
	}
	if _, err := app.CaseSetMeta("  ", "", ""); err == nil {
		t.Error("accepted a blank name")
	}
}

func TestCaseSaveAndReopen(t *testing.T) {
	app := newTestApp(t)
	st, err := app.CaseNew("Operation Nightfall", "A. Analyst", "laptop")
	mustOpen(t, st, err)
	path := filepath.Join(t.TempDir(), "cases", "nightfall.json")
	res, err := app.CaseSave(path)
	if err != nil {
		t.Fatalf("CaseSave: %v", err)
	}
	if res.Mode != "case" || res.BytesSaved <= 0 || res.SHA256 == "" {
		t.Errorf("SaveResult = %+v", res)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if res.SHA256 != stdhex.EncodeToString(sum[:]) {
		t.Errorf("SHA256 = %s, want %s", res.SHA256, stdhex.EncodeToString(sum[:]))
	}

	if _, err := app.CaseSave("  "); err == nil {
		t.Error("accepted an empty destination")
	}
	if _, err := app.CaseSave(path); err != nil {
		// Saving over an existing case is allowed: it is the analyst's own file.
		t.Errorf("re-save: %v", err)
	}
	if err := app.CaseClose(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.CaseSave(path); !errors.Is(err, errNoCase) {
		t.Errorf("saving with no case: %v", err)
	}

	st, err = app.CaseOpen(path)
	mustOpen(t, st, err)
	if st.Case.Name != "Operation Nightfall" || st.Path != path {
		t.Errorf("reopened = %+v", st)
	}
	if logged := caseAudit(t, app); !strings.Contains(logged, `"op":"save"`) || !strings.Contains(logged, `"op":"open"`) {
		t.Errorf("audit log is missing save/open entries:\n%s", logged)
	}
}

func TestCaseOpenErrors(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.CaseOpen("   "); err == nil {
		t.Error("accepted an empty path")
	}
	missing := filepath.Join(t.TempDir(), "nope.json")
	if _, err := app.CaseOpen(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file err = %v", err)
	}

	foreign := filepath.Join(t.TempDir(), "foreign.json")
	if err := os.WriteFile(foreign, []byte(`{"hello":"world"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.CaseOpen(foreign); !errors.Is(err, forensics.ErrNotCase) {
		t.Errorf("foreign file err = %v, want ErrNotCase", err)
	}

	// An open case refuses a second open until it is closed.
	_, err := app.CaseNew("first", "", "")
	mustOk(t, err)
	path := filepath.Join(t.TempDir(), "case.json")
	if _, err := app.CaseSave(path); err != nil {
		t.Fatal(err)
	}
	if err := app.CaseClose(); err != nil {
		t.Fatal(err)
	}
	_, err = app.CaseOpen(path)
	mustOk(t, err)
	if _, err := app.CaseOpen(path); err == nil {
		t.Error("opened a second case while one was open")
	}
	if logged := caseAudit(t, app); !strings.Contains(logged, `"result":"error"`) {
		t.Errorf("a failed open must be audited:\n%s", logged)
	}
}

func TestCaseEvidenceAddAndVerify(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.CaseEvidenceAdd("/tmp/x", forensics.KindFile, ""); !errors.Is(err, errNoCase) {
		t.Errorf("with no case: %v", err)
	}
	_, err := app.CaseNew("Evidence case", "A", "")
	mustOk(t, err)
	payload := []byte("original evidence bytes")
	path := writeFile(t, "evidence.bin", payload)

	st, err := app.CaseEvidenceAdd(path, forensics.KindFile, "from disk")
	mustOpen(t, st, err)
	if len(st.Case.Evidence) != 1 {
		t.Fatalf("evidence = %+v", st.Case.Evidence)
	}
	ev := st.Case.Evidence[0]
	if ev.ID != "e-001" || ev.Kind != forensics.KindFile || ev.Size != int64(len(payload)) {
		t.Errorf("entry = %+v", ev)
	}
	sum := sha256.Sum256(payload)
	if ev.SHA256 != stdhex.EncodeToString(sum[:]) {
		t.Errorf("sha256 = %s", ev.SHA256)
	}

	res, err := app.CaseEvidenceVerify(ev.ID)
	if err != nil {
		t.Fatalf("CaseEvidenceVerify: %v", err)
	}
	if !res.Match || res.Actual != ev.SHA256 {
		t.Errorf("verify = %+v", res)
	}

	// The same file twice is refused: one case, one entry per object.
	if _, err := app.CaseEvidenceAdd(path, forensics.KindFile, ""); err == nil {
		t.Error("added the same file twice")
	}
	if _, err := app.CaseEvidenceAdd(writeFile(t, "other.bin", []byte("x")), "mystery", ""); err == nil {
		t.Error("accepted an unknown evidence kind")
	}
	if _, err := app.CaseEvidenceAdd(filepath.Join(t.TempDir(), "gone.bin"), forensics.KindFile, ""); err == nil {
		t.Error("accepted a missing file")
	}

	// Tampering must be visible, and must be an error in the audit log.
	if err := os.WriteFile(path, []byte("tampered evidence"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = app.CaseEvidenceVerify(ev.ID)
	if err != nil {
		t.Fatalf("verify after tamper: %v", err)
	}
	if res.Match {
		t.Error("tampered file reported a match")
	}
	if _, err := app.CaseEvidenceVerify("e-999"); err == nil {
		t.Error("verified an unknown item")
	}

	logged := caseAudit(t, app)
	if !strings.Contains(logged, `"op":"import"`) {
		t.Errorf("audit log has no import entry:\n%s", logged)
	}
	if !strings.Contains(logged, `"match":"false"`) {
		t.Errorf("audit log does not record the mismatch:\n%s", logged)
	}
}

func TestCaseEvidenceAfterClose(t *testing.T) {
	app := newTestApp(t)
	_, err := app.CaseNew("c", "", "")
	mustOk(t, err)
	if err := app.CaseClose(); err != nil {
		t.Fatal(err)
	}
	path := writeFile(t, "a.bin", []byte("data"))
	if _, err := app.CaseEvidenceAdd(path, forensics.KindFile, ""); !errors.Is(err, errNoCase) {
		t.Errorf("err = %v, want errNoCase", err)
	}
	if _, err := app.CaseEvidenceVerify("e-001"); !errors.Is(err, errNoCase) {
		t.Errorf("verify err = %v, want errNoCase", err)
	}
}

func TestCaseFindingsAndEvents(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.CaseFindingAdd(FindingInput{Title: "t"}); !errors.Is(err, errNoCase) {
		t.Errorf("finding with no case: %v", err)
	}
	if _, err := app.CaseEventAdd(forensics.Event{Summary: "s"}); !errors.Is(err, errNoCase) {
		t.Errorf("event with no case: %v", err)
	}

	_, err := app.CaseNew("c", "", "")
	mustOk(t, err)
	path := writeFile(t, "ev.bin", []byte("payload"))
	st, err := app.CaseEvidenceAdd(path, forensics.KindFile, "")
	mustOpen(t, st, err)
	id := st.Case.Evidence[0].ID

	st, err = app.CaseFindingAdd(FindingInput{
		Title: "Exfiltration", Severity: forensics.SeverityHigh, EvidenceID: id,
	})
	mustOpen(t, st, err)
	if len(st.Case.Findings) != 1 || st.Case.Findings[0].ID != "f-001" {
		t.Errorf("findings = %+v", st.Case.Findings)
	}
	if _, err := app.CaseFindingAdd(FindingInput{Title: "t", Severity: "extreme"}); err == nil {
		t.Error("accepted an unknown severity")
	}
	if _, err := app.CaseFindingAdd(FindingInput{Title: "t", EvidenceID: "e-9"}); err == nil {
		t.Error("accepted a finding pointing at nothing")
	}

	st, err = app.CaseEventAdd(forensics.Event{
		Source: "browser:Chrome", Kind: forensics.EventVisit,
		Summary: "visited example.test", EvidenceID: id,
	})
	mustOpen(t, st, err)
	if len(st.Case.Events) != 1 || st.Case.Events[0].Summary != "visited example.test" {
		t.Errorf("events = %+v", st.Case.Events)
	}
	if _, err := app.CaseEventAdd(forensics.Event{Kind: forensics.EventManual}); err == nil {
		t.Error("accepted an event with no summary")
	}
	if _, err := app.CaseEventAdd(forensics.Event{Summary: "s", EvidenceID: "e-9"}); err == nil {
		t.Error("accepted an event pointing at nothing")
	}
}

func TestCaseReportHTML(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.CaseReport("html", "x.html"); !errors.Is(err, errNoCase) {
		t.Errorf("with no case: %v", err)
	}
	_, err := app.CaseNew("Operation Nightfall", "A. Analyst", "laptop")
	mustOk(t, err)
	path := writeFile(t, "ev.bin", []byte("payload"))
	st, err := app.CaseEvidenceAdd(path, forensics.KindFile, "")
	mustOpen(t, st, err)
	if _, err := app.CaseFindingAdd(FindingInput{
		Title: "Staging host", EvidenceID: st.Case.Evidence[0].ID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.CaseEventAdd(forensics.Event{
		Source: "carve", Kind: forensics.EventCarve, Summary: "photo.jpg",
	}); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "report.html")
	res, err := app.CaseReport("HTML", dst)
	if err != nil {
		t.Fatalf("CaseReport: %v", err)
	}
	if res.Mode != "report" || res.SHA256 == "" || res.BytesSaved <= 0 {
		t.Errorf("SaveResult = %+v", res)
	}
	body, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if res.SHA256 != stdhex.EncodeToString(sum[:]) {
		t.Errorf("SHA256 = %s, want %s", res.SHA256, stdhex.EncodeToString(sum[:]))
	}
	for _, want := range []string{"Operation Nightfall", "Staging host", "photo.jpg", "Forensic case report"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("report is missing %q", want)
		}
	}

	// A report never overwrites: the second attempt must fail and leave the
	// first one intact.
	if _, err := app.CaseReport("html", dst); err == nil {
		t.Error("overwrote an existing report")
	}
	again, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != len(body) {
		t.Error("the refused export damaged the existing report")
	}

	if _, err := app.CaseReport("bogus", filepath.Join(t.TempDir(), "r.pdf")); err == nil {
		t.Error("accepted an unknown format")
	}
	if _, err := app.CaseReport("html", "  "); err == nil {
		t.Error("accepted an empty destination")
	}

	logged := caseAudit(t, app)
	if !strings.Contains(logged, `"op":"report"`) {
		t.Errorf("audit log has no report entry:\n%s", logged)
	}
}

func TestCaseReportJSON(t *testing.T) {
	app := newTestApp(t)
	_, err := app.CaseNew("JSON case", "A", "")
	mustOk(t, err)
	if _, err := app.CaseEventAdd(forensics.Event{
		Kind: forensics.EventManual, Summary: "first note",
	}); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "report.json")
	if _, err := app.CaseReport("json", dst); err != nil {
		t.Fatalf("CaseReport: %v", err)
	}
	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ReportFormat string `json:"reportFormat"`
		Checksum     string `json:"checksum"`
		Case         struct {
			Name string `json:"name"`
		} `json:"case"`
		Timeline []struct {
			Summary string `json:"summary"`
		} `json:"timeline"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if doc.ReportFormat != forensics.ReportFormat || len(doc.Checksum) != 64 {
		t.Errorf("format/checksum = %q / %q", doc.ReportFormat, doc.Checksum)
	}
	if doc.Case.Name != "JSON case" || len(doc.Timeline) != 1 || doc.Timeline[0].Summary != "first note" {
		t.Errorf("report = %+v", doc)
	}
}

func TestCaseEvidenceDirRejected(t *testing.T) {
	app := newTestApp(t)
	_, err := app.CaseNew("c", "", "")
	mustOk(t, err)
	if _, err := app.CaseEvidenceAdd(t.TempDir(), forensics.KindFile, ""); err == nil {
		t.Error("added a directory as evidence")
	}
}

func TestCaseReportPDFAndDOCX(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.CaseNew("PDF case", "B", "for rendering"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.CaseEventAdd(forensics.Event{
		Kind: forensics.EventManual, Summary: "note for pdf",
	}); err != nil {
		t.Fatal(err)
	}

	pdfDst := filepath.Join(t.TempDir(), "report.pdf")
	res, err := app.CaseReport("PDF", pdfDst)
	if err != nil {
		t.Fatalf("CaseReport(pdf): %v", err)
	}
	if res.BytesSaved == 0 {
		t.Fatal("empty PDF")
	}
	body, err := os.ReadFile(pdfDst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(body, []byte("%PDF-1.4")) {
		t.Fatalf("PDF header = %q", body[:10])
	}
	if !bytes.Contains(body, []byte("GoHex Forensic Case Report")) {
		t.Error("PDF missing title text")
	}
	if !bytes.HasSuffix(bytes.TrimSpace(body), []byte("%%EOF")) {
		t.Error("PDF missing EOF marker")
	}

	docxDst := filepath.Join(t.TempDir(), "report.docx")
	res2, err := app.CaseReport("docx", docxDst)
	if err != nil {
		t.Fatalf("CaseReport(docx): %v", err)
	}
	if res2.BytesSaved == 0 {
		t.Fatal("empty DOCX")
	}
	dbody, err := os.ReadFile(docxDst)
	if err != nil {
		t.Fatal(err)
	}
	// A .docx is a ZIP; check the PK header and required parts.
	if !bytes.HasPrefix(dbody, []byte("PK\x03\x04")) {
		t.Fatalf("DOCX header = %q", dbody[:4])
	}
	zr, err := zip.NewReader(bytes.NewReader(dbody), int64(len(dbody)))
	if err != nil {
		t.Fatalf("DOCX is not a valid zip: %v", err)
	}
	wantParts := map[string]bool{
		"[Content_Types].xml":          false,
		"_rels/.rels":                  false,
		"word/document.xml":            false,
		"word/_rels/document.xml.rels": false,
	}
	for _, f := range zr.File {
		if _, ok := wantParts[f.Name]; ok {
			wantParts[f.Name] = true
		}
	}
	for name, found := range wantParts {
		if !found {
			t.Errorf("DOCX missing part %s", name)
		}
	}
	// document.xml must carry the case name.
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			content, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(content, []byte("PDF case")) {
				t.Error("document.xml missing case name")
			}
		}
	}
}
