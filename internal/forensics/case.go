// Package forensics is GoHex's casework layer. It records what was examined,
// when it was added, what it hashed to and what the examiner concluded, and
// it renders that record as a report.
//
// A case is an ordinary JSON document carrying a schema version, so it can be
// diffed, reviewed and archived with standard tooling. It never contains
// evidence bytes: evidence stays where it is and is referenced by path, size
// and SHA-256, which is exactly what chain of custody needs. Nothing in this
// package writes to evidence.
package forensics

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/IshikawaUta/gohex/pkg/version"
)

// SchemaVersion is the case-file format this build writes. A file claiming a
// higher version is rejected rather than half-understood.
const SchemaVersion = 1

// ReportFormat identifies the report document emitted by BuildReport.
const ReportFormat = "gohex-report-v1"

// Errors returned by Open.
var (
	ErrNotCase      = errors.New("forensics: not a GoHex case file")
	ErrSchemaTooNew = errors.New("forensics: case file uses a newer schema")
)

// Evidence kinds. A kind is a claim about where a thing came from, so it is
// restricted to a known set instead of free text.
const (
	KindImage  = "image"  // disk image or block device
	KindFile   = "file"   // loose file
	KindCarved = "carved" // output of the carver
	KindExport = "export" // output of another export (report, browser artefact)
	KindOther  = "other"
)

// Finding severities.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Event kinds for the timeline.
const (
	EventVisit    = "visit"    // browser history entry
	EventDownload = "download" // browser download
	EventFS       = "fs"       // file-system timestamp
	EventCarve    = "carve"    // carved object
	EventEvidence = "evidence" // evidence added to the case
	EventManual   = "manual"   // typed by the examiner
	EventExport   = "export"   // something exported by the tool
)

var (
	kinds         = []string{KindImage, KindFile, KindCarved, KindExport, KindOther}
	severities    = []string{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	hex32         = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	errBadKind    = errors.New("forensics: unknown evidence kind")
	errBadSev     = errors.New("forensics: unknown severity")
	errDupPath    = errors.New("forensics: that file is already in this case")
	errDupID      = errors.New("forensics: duplicate identifier")
	errNoEvidence = errors.New("forensics: no such evidence item")
)

// ValidKind reports whether k is one of the recognised evidence kinds.
func ValidKind(k string) bool { return contains(kinds, k) }

// ValidSeverity reports whether s is one of the recognised severities.
func ValidSeverity(s string) bool { return contains(severities, s) }

// ToolInfo records which build produced the case, so a report opened years
// later still says what wrote it.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	GOOS    string `json:"goos"`
}

// Evidence is one examined object. SHA256 is the digest of the file as it was
// when it was added; VerifyEvidence recomputes it to prove the file has not
// changed since.
type Evidence struct {
	ID      string    `json:"id"`
	Path    string    `json:"path"`
	Kind    string    `json:"kind"`
	Size    int64     `json:"size"`
	SHA256  string    `json:"sha256"`
	AddedAt time.Time `json:"addedAt"`
	Note    string    `json:"note,omitempty"`
	// BatesID is stamped by ApplyBates on report copies only; it is
	// never persisted into the case file.
	BatesID string `json:"batesId,omitempty"`
}

// Finding is the examiner's conclusion about one thing.
type Finding struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Detail     string    `json:"detail,omitempty"`
	Severity   string    `json:"severity"`
	EvidenceID string    `json:"evidenceId,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
}

// Event is one point on the timeline. Times are stored in UTC; a zero time
// means the source did not record one.
type Event struct {
	Time       time.Time `json:"time"`
	Source     string    `json:"source"`
	Kind       string    `json:"kind"`
	Summary    string    `json:"summary"`
	EvidenceID string    `json:"evidenceId,omitempty"`
	// BatesID is stamped by ApplyBates on report copies only.
	BatesID string `json:"batesId,omitempty"`
}

// Case is the case file.
type Case struct {
	SchemaVersion int        `json:"schemaVersion"`
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Examiner      string     `json:"examiner,omitempty"`
	Description   string     `json:"description,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	ModifiedAt    time.Time  `json:"modifiedAt"`
	Tool          ToolInfo   `json:"tool"`
	Evidence      []Evidence `json:"evidence"`
	Findings      []Finding  `json:"findings,omitempty"`
	Events        []Event    `json:"events,omitempty"`
}

// New starts an empty case. Name is required; the rest are optional.
func New(name, examiner, description string) (*Case, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("forensics: a case needs a name")
	}
	now := time.Now().UTC()
	return &Case{
		SchemaVersion: SchemaVersion,
		ID:            newID("case"),
		Name:          name,
		Examiner:      strings.TrimSpace(examiner),
		Description:   strings.TrimSpace(description),
		CreatedAt:     now,
		ModifiedAt:    now,
		Tool:          CurrentTool(),
	}, nil
}

// CurrentTool describes this build.
func CurrentTool() ToolInfo {
	return ToolInfo{Name: "GoHex", Version: version.Version, GOOS: runtime.GOOS}
}

// Open reads a case file. A file that is not JSON, or JSON that does not look
// like a case, is ErrNotCase; a file from a future schema is ErrSchemaTooNew.
func Open(path string) (*Case, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Case
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotCase, err)
	}
	if c.SchemaVersion == 0 {
		return nil, ErrNotCase
	}
	if c.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("%w: file is v%d, this build reads up to v%d",
			ErrSchemaTooNew, c.SchemaVersion, SchemaVersion)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save writes the case atomically: a temporary file in the same directory is
// written, flushed and renamed over the destination, so an interrupted write
// can never leave a half-written case file behind. The file is 0600 — a case
// names people and systems and is not world-readable by default.
func (c *Case) Save(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("forensics: empty case path")
	}
	if c.SchemaVersion == 0 {
		c.SchemaVersion = SchemaVersion
	}
	if c.Tool == (ToolInfo{}) {
		c.Tool = CurrentTool()
	}
	c.ModifiedAt = time.Now().UTC()
	if err := c.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".case-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, abs)
}

// Validate checks the invariants a report depends on: a name, a schema
// version, unique identifiers, and known kinds and severities.
func (c *Case) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("forensics: case has no name")
	}
	if c.SchemaVersion == 0 {
		return errors.New("forensics: case has no schema version")
	}
	ids := make(map[string]bool, len(c.Evidence)+len(c.Findings))
	for _, e := range c.Evidence {
		if e.ID == "" {
			return errors.New("forensics: evidence item without an id")
		}
		if ids[e.ID] {
			return fmt.Errorf("%w: %s", errDupID, e.ID)
		}
		ids[e.ID] = true
		if !ValidKind(e.Kind) {
			return fmt.Errorf("%w: %q", errBadKind, e.Kind)
		}
		if strings.TrimSpace(e.Path) == "" {
			return errors.New("forensics: evidence item without a path")
		}
		if e.SHA256 != "" && !hex32.MatchString(e.SHA256) {
			return fmt.Errorf("forensics: evidence %s has a malformed sha256", e.ID)
		}
	}
	for _, f := range c.Findings {
		if f.ID == "" {
			return errors.New("forensics: finding without an id")
		}
		if ids[f.ID] {
			return fmt.Errorf("%w: %s", errDupID, f.ID)
		}
		ids[f.ID] = true
		if !ValidSeverity(f.Severity) {
			return fmt.Errorf("%w: %q", errBadSev, f.Severity)
		}
	}
	return nil
}

// SetMeta updates the descriptive fields of an open case.
func (c *Case) SetMeta(name, examiner, description string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("forensics: a case needs a name")
	}
	c.Name = name
	c.Examiner = strings.TrimSpace(examiner)
	c.Description = strings.TrimSpace(description)
	return nil
}

// EvidenceFromPath builds an Evidence entry for path: it stats the file and
// streams it through SHA-256. The file is opened read-only; a path that has
// vanished since the picker chose it is an error rather than a hollow entry.
func EvidenceFromPath(path, kind, note string) (Evidence, error) {
	if strings.TrimSpace(path) == "" {
		return Evidence{}, errors.New("forensics: empty evidence path")
	}
	if kind == "" {
		kind = KindFile
	}
	if !ValidKind(kind) {
		return Evidence{}, fmt.Errorf("%w: %q", errBadKind, kind)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return Evidence{}, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return Evidence{}, err
	}
	if st.IsDir() {
		return Evidence{}, fmt.Errorf("forensics: %s is a directory", abs)
	}
	sum, err := fileSHA256(abs)
	if err != nil {
		return Evidence{}, err
	}
	return Evidence{
		Path:    abs,
		Kind:    kind,
		Size:    st.Size(),
		SHA256:  sum,
		AddedAt: time.Now().UTC(),
		Note:    strings.TrimSpace(note),
	}, nil
}

// AddEvidence puts an entry into the case. The identifier is assigned here so
// a caller cannot collide one with a finding.
func (c *Case) AddEvidence(e Evidence) error {
	if e.ID == "" {
		e.ID = c.nextID("e", func(s string) bool { return evidenceID(c, s) == nil })
	}
	if strings.TrimSpace(e.Path) == "" {
		return errors.New("forensics: evidence needs a path")
	}
	if e.Kind == "" {
		e.Kind = KindFile
	}
	if !ValidKind(e.Kind) {
		return fmt.Errorf("%w: %q", errBadKind, e.Kind)
	}
	if e.SHA256 != "" && !hex32.MatchString(e.SHA256) {
		return errors.New("forensics: evidence sha256 must be 64 hex characters")
	}
	if e.AddedAt.IsZero() {
		e.AddedAt = time.Now().UTC()
	}
	for _, have := range c.Evidence {
		if have.ID == e.ID {
			return fmt.Errorf("%w: %s", errDupID, e.ID)
		}
		if have.Path == e.Path {
			return errDupPath
		}
	}
	c.Evidence = append(c.Evidence, e)
	return nil
}

// AddFinding records a conclusion. An empty severity means "info" rather than
// an error: not every finding needs grading, but every finding is graded.
func (c *Case) AddFinding(f Finding) error {
	if strings.TrimSpace(f.Title) == "" {
		return errors.New("forensics: finding needs a title")
	}
	if f.Severity == "" {
		f.Severity = SeverityInfo
	}
	if !ValidSeverity(f.Severity) {
		return fmt.Errorf("%w: %q", errBadSev, f.Severity)
	}
	if f.EvidenceID != "" {
		if _, err := c.findEvidence(f.EvidenceID); err != nil {
			return err
		}
	}
	if f.ID == "" {
		f.ID = c.nextID("f", func(s string) bool { return findingID(c, s) == nil })
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now().UTC()
	}
	c.Findings = append(c.Findings, f)
	return nil
}

// AddEvent puts one point on the timeline. A summary is required — an event
// nobody can read is not evidence of anything.
func (c *Case) AddEvent(e Event) error {
	if strings.TrimSpace(e.Summary) == "" {
		return errors.New("forensics: event needs a summary")
	}
	if e.Kind == "" {
		e.Kind = EventManual
	}
	if e.EvidenceID != "" {
		if _, err := c.findEvidence(e.EvidenceID); err != nil {
			return err
		}
	}
	if !e.Time.IsZero() {
		e.Time = e.Time.UTC()
	}
	c.Events = append(c.Events, e)
	return nil
}

// Timeline returns the events ordered oldest first. Events with no recorded
// time come last, keeping their insertion order — an unknown time is not the
// same as an early one.
func (c *Case) Timeline() []Event {
	out := make([]Event, len(c.Events))
	copy(out, c.Events)
	sort.SliceStable(out, func(i, j int) bool {
		ti, tj := out[i].Time, out[j].Time
		if ti.IsZero() != tj.IsZero() {
			return !ti.IsZero()
		}
		if ti.IsZero() {
			return false
		}
		return ti.Before(tj)
	})
	return out
}

// FindEvidence returns the entry with the given identifier.
func (c *Case) FindEvidence(id string) (Evidence, error) { return c.findEvidence(id) }

// VerifyEvidence re-hashes the file behind one evidence entry and reports
// whether it still matches what was recorded when it was added. A missing
// file is an error, not a mismatch — nothing was checked at all.
func (c *Case) VerifyEvidence(id string) (VerifyResult, error) {
	e, err := c.findEvidence(id)
	if err != nil {
		return VerifyResult{}, err
	}
	sum, err := fileSHA256(e.Path)
	if err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{
		EvidenceID: e.ID,
		Path:       e.Path,
		Expected:   e.SHA256,
		Actual:     sum,
		Match:      strings.EqualFold(e.SHA256, sum),
		CheckedAt:  time.Now().UTC(),
	}, nil
}

// VerifyResult is the outcome of re-hashing one evidence item.
type VerifyResult struct {
	EvidenceID string    `json:"evidenceId"`
	Path       string    `json:"path"`
	Expected   string    `json:"expected"`
	Actual     string    `json:"actual"`
	Match      bool      `json:"match"`
	CheckedAt  time.Time `json:"checkedAt"`
}

func (c *Case) findEvidence(id string) (Evidence, error) {
	for _, e := range c.Evidence {
		if e.ID == id {
			return e, nil
		}
	}
	return Evidence{}, fmt.Errorf("%w: %s", errNoEvidence, id)
}

// nextID returns prefix-001, prefix-002, … skipping any already taken.
func (c *Case) nextID(prefix string, free func(string) bool) string {
	for i := 1; i < 1_000_000; i++ {
		id := fmt.Sprintf("%s-%03d", prefix, i)
		if free(id) {
			return id
		}
	}
	return prefix + "-" + newID("x")
}

func evidenceID(c *Case, id string) error {
	for _, e := range c.Evidence {
		if e.ID == id {
			return errDupID
		}
	}
	return nil
}

func findingID(c *Case, id string) error {
	for _, f := range c.Findings {
		if f.ID == id {
			return errDupID
		}
	}
	return nil
}

// newID returns a short random identifier: readable in a report, and not
// guessable from the wall clock.
func newID(prefix string) string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
