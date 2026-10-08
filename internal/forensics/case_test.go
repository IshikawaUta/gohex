package forensics

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNew(t *testing.T) {
	c, err := New("  Operation Nightfall  ", " A. Analyst ", " seized laptop")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Name != "Operation Nightfall" || c.Examiner != "A. Analyst" || c.Description != "seized laptop" {
		t.Errorf("fields not trimmed: %+v", c)
	}
	if c.SchemaVersion != SchemaVersion {
		t.Errorf("schema = %d, want %d", c.SchemaVersion, SchemaVersion)
	}
	if c.ID == "" || !strings.HasPrefix(c.ID, "case-") {
		t.Errorf("id = %q", c.ID)
	}
	if c.CreatedAt.IsZero() || c.ModifiedAt.IsZero() {
		t.Error("timestamps not set")
	}
	if c.Tool.Name != "GoHex" || c.Tool.Version == "" || c.Tool.GOOS == "" {
		t.Errorf("tool = %+v", c.Tool)
	}
	if len(c.Evidence) != 0 || len(c.Findings) != 0 || len(c.Events) != 0 {
		t.Error("new case is not empty")
	}
	if _, err := New("  ", "", ""); err == nil {
		t.Error("accepted a blank case name")
	}
}

func TestSetMeta(t *testing.T) {
	c, _ := New("old", "someone", "desc")
	if err := c.SetMeta("new", " B ", "d2"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if c.Name != "new" || c.Examiner != "B" || c.Description != "d2" {
		t.Errorf("meta = %+v", c)
	}
	if err := c.SetMeta("", "", ""); err == nil {
		t.Error("accepted a blank name")
	}
}

func TestSaveAndOpenRoundTrip(t *testing.T) {
	c, _ := New("Case A", "examiner", "note")
	ev := Evidence{Path: "/evidence/disk.dd", Kind: KindImage, Size: 4096,
		SHA256: strings.Repeat("ab", 32), AddedAt: time.Now().UTC()}
	if err := c.AddEvidence(ev); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	if err := c.AddFinding(Finding{Title: "suspicious", Severity: SeverityHigh, EvidenceID: "e-001"}); err != nil {
		t.Fatalf("AddFinding: %v", err)
	}
	if err := c.AddEvent(Event{Time: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		Source: "browser:Chrome", Kind: EventVisit, Summary: "visited example.test"}); err != nil {
		t.Fatalf("AddEvent: %v", err)
	}

	path := filepath.Join(t.TempDir(), "sub", "case.json")
	if err := c.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("case file mode = %o, want 600", perm)
	}

	got, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Name != c.Name || got.ID != c.ID || got.Examiner != c.Examiner {
		t.Errorf("round trip lost metadata: %+v", got)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].Path != ev.Path {
		t.Errorf("evidence = %+v", got.Evidence)
	}
	if len(got.Findings) != 1 || got.Findings[0].Severity != SeverityHigh {
		t.Errorf("findings = %+v", got.Findings)
	}
	if len(got.Events) != 1 || got.Events[0].Summary != "visited example.test" {
		t.Errorf("events = %+v", got.Events)
	}
	if got.SchemaVersion != SchemaVersion || got.Tool.Name != "GoHex" {
		t.Errorf("schema/tool = %d/%+v", got.SchemaVersion, got.Tool)
	}

	// Saving again must not duplicate or lose anything, and must leave no
	// temporary files behind in the directory.
	if err := got.Save(path); err != nil {
		t.Fatalf("re-save: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries after two saves, want 1", len(entries))
	}
}

func TestSaveErrors(t *testing.T) {
	c, _ := New("x", "", "")
	if err := c.Save("   "); err == nil {
		t.Error("accepted an empty path")
	}
	broken := &Case{Name: "n", Evidence: []Evidence{{ID: "e-001", Path: "/p", Kind: "nope"}}}
	if err := broken.Save(filepath.Join(t.TempDir(), "c.json")); err == nil {
		t.Error("saved an invalid case")
	}
}

func TestOpenErrors(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.json")
	if _, err := Open(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file err = %v", err)
	}

	notJSON := filepath.Join(dir, "plain.json")
	if err := os.WriteFile(notJSON, []byte("just text"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(notJSON); !errors.Is(err, ErrNotCase) {
		t.Errorf("non-JSON err = %v, want ErrNotCase", err)
	}

	wrongJSON := filepath.Join(dir, "wrong.json")
	if err := os.WriteFile(wrongJSON, []byte(`{"name":"a case"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(wrongJSON); !errors.Is(err, ErrNotCase) {
		t.Errorf("JSON without schema err = %v, want ErrNotCase", err)
	}

	future := filepath.Join(dir, "future.json")
	if err := os.WriteFile(future, []byte(`{"schemaVersion":99,"name":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(future); !errors.Is(err, ErrSchemaTooNew) {
		t.Errorf("future schema err = %v, want ErrSchemaTooNew", err)
	}

	invalid := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalid, []byte(`{"schemaVersion":1,"name":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(invalid); err == nil {
		t.Error("opened a case that fails validation")
	}
}

func TestValidate(t *testing.T) {
	ok := func(c *Case, wantErr bool) {
		t.Helper()
		err := c.Validate()
		if (err != nil) != wantErr {
			t.Errorf("Validate(%+v) = %v, wantErr=%v", c, err, wantErr)
		}
	}
	ok(&Case{}, true)
	ok(&Case{Name: "n"}, true)
	ok(&Case{Name: "n", SchemaVersion: SchemaVersion}, false)
	ok(&Case{Name: "n", SchemaVersion: SchemaVersion, Evidence: []Evidence{
		{ID: "e-001", Path: "/a", Kind: KindFile},
		{ID: "e-001", Path: "/b", Kind: KindFile},
	}}, true)
	ok(&Case{Name: "n", SchemaVersion: SchemaVersion, Evidence: []Evidence{
		{ID: "e-001", Path: "/a", Kind: "mystery"},
	}}, true)
	ok(&Case{Name: "n", SchemaVersion: SchemaVersion, Evidence: []Evidence{
		{ID: "e-001", Path: "/a", Kind: KindFile},
	}}, false)
	ok(&Case{Name: "n", SchemaVersion: SchemaVersion, Evidence: []Evidence{
		{ID: "e-001", Path: "", Kind: KindFile},
	}}, true)
	ok(&Case{Name: "n", SchemaVersion: SchemaVersion, Evidence: []Evidence{
		{ID: "e-001", Path: "/a", Kind: KindFile, SHA256: "not-hex"},
	}}, true)
	ok(&Case{Name: "n", SchemaVersion: SchemaVersion, Evidence: []Evidence{
		{ID: "e-001", Path: "/a", Kind: KindFile},
	}, Findings: []Finding{
		{ID: "f-001", Title: "t", Severity: "extreme"},
	}}, true)
	ok(&Case{Name: "n", SchemaVersion: SchemaVersion, Findings: []Finding{
		{Title: "t", Severity: SeverityLow},
	}}, true)
	// Identifiers share one namespace across evidence and findings.
	ok(&Case{Name: "n", SchemaVersion: SchemaVersion,
		Evidence: []Evidence{{ID: "e-001", Path: "/a", Kind: KindFile}},
		Findings: []Finding{{ID: "e-001", Title: "t", Severity: SeverityLow}},
	}, true)
}

func TestEvidenceFromPath(t *testing.T) {
	path := writeFixture(t, "disk.dd", "hello evidence")
	ev, err := EvidenceFromPath(path, "", "")
	if err != nil {
		t.Fatalf("EvidenceFromPath: %v", err)
	}
	if !filepath.IsAbs(ev.Path) {
		t.Errorf("path %q is not absolute", ev.Path)
	}
	if ev.Kind != KindFile {
		t.Errorf("default kind = %q, want file", ev.Kind)
	}
	if ev.Size != int64(len("hello evidence")) {
		t.Errorf("size = %d", ev.Size)
	}
	// SHA-256("hello evidence")
	want := "9af4c73b2a919f220f4b008e466b52808a1987122d95ff0f2dde00968e36e844"
	if ev.SHA256 != want {
		t.Errorf("sha256 = %s, want %s", ev.SHA256, want)
	}
	if ev.AddedAt.IsZero() {
		t.Error("AddedAt not set")
	}

	if _, err := EvidenceFromPath("", KindFile, ""); err == nil {
		t.Error("accepted an empty path")
	}
	if _, err := EvidenceFromPath(path, "mystery", ""); err == nil {
		t.Error("accepted an unknown kind")
	}
	if _, err := EvidenceFromPath(filepath.Join(t.TempDir(), "gone.dd"), KindFile, ""); err == nil {
		t.Error("accepted a missing file")
	}
	if _, err := EvidenceFromPath(t.TempDir(), KindFile, ""); err == nil {
		t.Error("accepted a directory")
	}
	ev2, err := EvidenceFromPath(path, KindImage, " noted ")
	if err != nil {
		t.Fatalf("with kind: %v", err)
	}
	if ev2.Kind != KindImage || ev2.Note != "noted" {
		t.Errorf("kind/note = %q/%q", ev2.Kind, ev2.Note)
	}
}

func TestAddEvidenceIDsAndDuplicates(t *testing.T) {
	c, _ := New("c", "", "")
	base := Evidence{Path: "/a.dd", Kind: KindImage, Size: 10, SHA256: strings.Repeat("0a", 32)}
	if err := c.AddEvidence(base); err != nil {
		t.Fatalf("first: %v", err)
	}
	second := base
	second.Path = "/b.dd"
	if err := c.AddEvidence(second); err != nil {
		t.Fatalf("second: %v", err)
	}
	if c.Evidence[0].ID != "e-001" || c.Evidence[1].ID != "e-002" {
		t.Errorf("ids = %q, %q", c.Evidence[0].ID, c.Evidence[1].ID)
	}
	if c.Evidence[1].AddedAt.IsZero() {
		t.Error("AddedAt not defaulted")
	}

	dup := base
	if err := c.AddEvidence(dup); !errors.Is(err, errDupPath) {
		t.Errorf("duplicate path err = %v", err)
	}
	clash := base
	clash.Path = "/c.dd"
	clash.ID = "e-001"
	if err := c.AddEvidence(clash); !errors.Is(err, errDupID) {
		t.Errorf("duplicate id err = %v", err)
	}
	if err := c.AddEvidence(Evidence{Path: "/d.dd", Kind: KindFile, SHA256: "zz"}); err == nil {
		t.Error("accepted a malformed digest")
	}
	if err := c.AddEvidence(Evidence{Path: "", Kind: KindFile}); err == nil {
		t.Error("accepted an empty path")
	}
	if err := c.AddEvidence(Evidence{Path: "/e.dd", Kind: "mystery"}); !errors.Is(err, errBadKind) {
		t.Errorf("kind err = %v", err)
	}
}

func TestAddFinding(t *testing.T) {
	c, _ := New("c", "", "")
	if err := c.AddFinding(Finding{Title: "  "}); err == nil {
		t.Error("accepted a blank title")
	}
	if err := c.AddFinding(Finding{Title: "t", Severity: "extreme"}); !errors.Is(err, errBadSev) {
		t.Errorf("severity err = %v", err)
	}
	if err := c.AddFinding(Finding{Title: "t", EvidenceID: "e-999"}); !errors.Is(err, errNoEvidence) {
		t.Errorf("evidence ref err = %v", err)
	}
	if err := c.AddFinding(Finding{Title: "first"}); err != nil {
		t.Fatalf("AddFinding: %v", err)
	}
	if c.Findings[0].ID != "f-001" || c.Findings[0].Severity != SeverityInfo {
		t.Errorf("finding = %+v", c.Findings[0])
	}
	if c.Findings[0].CreatedAt.IsZero() {
		t.Error("CreatedAt not set")
	}

	c2, _ := New("c2", "", "")
	if err := c2.AddEvidence(Evidence{Path: "/x", Kind: KindFile}); err != nil {
		t.Fatal(err)
	}
	if err := c2.AddFinding(Finding{Title: "t", Severity: SeverityMedium, EvidenceID: "e-001"}); err != nil {
		t.Fatalf("linked finding: %v", err)
	}
}

func TestAddEvent(t *testing.T) {
	c, _ := New("c", "", "")
	if err := c.AddEvent(Event{Kind: EventManual}); err == nil {
		t.Error("accepted an event without a summary")
	}
	if err := c.AddEvent(Event{Summary: "note", EvidenceID: "e-1"}); !errors.Is(err, errNoEvidence) {
		t.Errorf("evidence ref err = %v", err)
	}
	ist, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		ist = time.FixedZone("WIB", 7*3600)
	}
	when := time.Date(2024, 3, 4, 5, 6, 7, 0, ist)
	if err := c.AddEvent(Event{Time: when, Summary: "manual note"}); err != nil {
		t.Fatalf("AddEvent: %v", err)
	}
	if c.Events[0].Kind != EventManual {
		t.Errorf("default kind = %q", c.Events[0].Kind)
	}
	if _, off := c.Events[0].Time.Zone(); off != 0 {
		t.Errorf("event time kept offset %d, want UTC", off)
	}
}

func TestTimelineOrder(t *testing.T) {
	c, _ := New("c", "", "")
	mk := func(s string, tm time.Time) Event {
		return Event{Time: tm, Kind: EventManual, Summary: s}
	}
	mid := time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)
	c.Events = []Event{
		mk("unknown", time.Time{}),
		mk("later", mid.Add(2*time.Hour)),
		mk("middle", mid),
		mk("middle same", mid), // stable with respect to insertion order
	}
	got := c.Timeline()
	want := []string{"middle", "middle same", "later", "unknown"}
	if len(got) != len(want) {
		t.Fatalf("len = %d", len(got))
	}
	for i, w := range want {
		if got[i].Summary != w {
			t.Errorf("position %d = %q, want %q", i, got[i].Summary, w)
		}
	}
	if len(c.Events) != 4 {
		t.Error("Timeline mutated the case")
	}
}

func TestVerifyEvidence(t *testing.T) {
	path := writeFixture(t, "ev.bin", "original")
	c, _ := New("c", "", "")
	ev, err := EvidenceFromPath(path, KindFile, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddEvidence(ev); err != nil {
		t.Fatal(err)
	}

	res, err := c.VerifyEvidence("e-001")
	if err != nil {
		t.Fatalf("VerifyEvidence: %v", err)
	}
	if !res.Match {
		t.Errorf("unmodified file reported mismatch: %+v", res)
	}
	if res.Actual != ev.SHA256 || res.Expected != ev.SHA256 {
		t.Errorf("digests = %q / %q, want %q", res.Actual, res.Expected, ev.SHA256)
	}
	if res.CheckedAt.IsZero() {
		t.Error("CheckedAt not set")
	}

	if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = c.VerifyEvidence("e-001")
	if err != nil {
		t.Fatalf("VerifyEvidence after change: %v", err)
	}
	if res.Match {
		t.Error("tampered file still reported a match")
	}

	if _, err := c.VerifyEvidence("e-999"); !errors.Is(err, errNoEvidence) {
		t.Errorf("unknown id err = %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyEvidence("e-001"); err == nil {
		t.Error("verified a file that no longer exists")
	}
}

func TestKindAndSeveritySets(t *testing.T) {
	for _, k := range []string{KindImage, KindFile, KindCarved, KindExport, KindOther} {
		if !ValidKind(k) {
			t.Errorf("ValidKind(%q) = false", k)
		}
	}
	if ValidKind("exe") {
		t.Error(`ValidKind("exe") = true`)
	}
	for _, s := range []string{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if !ValidSeverity(s) {
			t.Errorf("ValidSeverity(%q) = false", s)
		}
	}
	if ValidSeverity("urgent") {
		t.Error(`ValidSeverity("urgent") = true`)
	}
}

func TestFindEvidence(t *testing.T) {
	c, _ := New("c", "", "")
	if err := c.AddEvidence(Evidence{Path: "/a", Kind: KindFile}); err != nil {
		t.Fatal(err)
	}
	got, err := c.FindEvidence("e-001")
	if err != nil || got.Path != "/a" {
		t.Fatalf("FindEvidence = %+v, %v", got, err)
	}
	if _, err := c.FindEvidence("nope"); !errors.Is(err, errNoEvidence) {
		t.Errorf("err = %v", err)
	}
}

func TestCaseFileIsPlainJSON(t *testing.T) {
	c, _ := New("json check", "e", "")
	path := filepath.Join(t.TempDir(), "case.json")
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("case file is not JSON: %v", err)
	}
	for _, key := range []string{"schemaVersion", "id", "name", "createdAt", "tool", "evidence"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("case file is missing %q", key)
		}
	}
}
