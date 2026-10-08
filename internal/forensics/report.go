package forensics

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"time"
)

// reportTemplate is the rendering of a report. It is embedded rather than
// read from disk so a single binary always produces the same document, and it
// is deliberately self-contained: no fonts, scripts or remote assets, so a
// report can be archived and still look right in twenty years.
//
//go:embed report/report.html
var reportTemplate string

// CaseSummary is the descriptive half of a case, carried into a report
// without the evidence list (which has its own section).
type CaseSummary struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Examiner    string    `json:"examiner,omitempty"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	ModifiedAt  time.Time `json:"modifiedAt"`
}

// ReportDocument is the machine-readable report. It is a flattened rendering
// of a case rather than the case itself: the timeline is pre-sorted and the
// case's own event order is not repeated, so what a consumer reads is exactly
// what the HTML shows.
type ReportDocument struct {
	ReportFormat string      `json:"reportFormat"`
	GeneratedAt  time.Time   `json:"generatedAt"`
	Tool         ToolInfo    `json:"tool"`
	Checksum     string      `json:"checksum"`
	Case         CaseSummary `json:"case"`
	Evidence     []Evidence  `json:"evidence"`
	Findings     []Finding   `json:"findings"`
	Timeline     []Event     `json:"timeline"`
}

// CaseChecksum returns the SHA-256 of the canonical (compact) JSON encoding
// of the case record. It is written into every report so that a reader can
// prove the report describes the case file they were given, independently of
// the pretty-printing of either document.
func CaseChecksum(c *Case) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// BuildReport renders a case into a report document. The timeline it carries
// is sorted by the same rules as Case.Timeline, so the HTML and the JSON
// cannot disagree about the order of events.
func BuildReport(c *Case, generatedAt time.Time) (ReportDocument, error) {
	if c == nil {
		return ReportDocument{}, fmt.Errorf("forensics: no case to report on")
	}
	sum, err := CaseChecksum(c)
	if err != nil {
		return ReportDocument{}, err
	}
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	doc := ReportDocument{
		ReportFormat: ReportFormat,
		GeneratedAt:  generatedAt.UTC(),
		Tool:         c.Tool,
		Checksum:     sum,
		Case: CaseSummary{
			ID:          c.ID,
			Name:        c.Name,
			Examiner:    c.Examiner,
			Description: c.Description,
			CreatedAt:   c.CreatedAt,
			ModifiedAt:  c.ModifiedAt,
		},
		Evidence: append([]Evidence{}, c.Evidence...),
		Findings: append([]Finding{}, c.Findings...),
		Timeline: c.Timeline(),
	}
	if doc.Tool == (ToolInfo{}) {
		doc.Tool = CurrentTool()
	}
	return doc, nil
}

// WriteJSON writes the report document, indented, terminated by a newline.
func WriteJSON(w io.Writer, c *Case, generatedAt time.Time) error {
	doc, err := BuildReport(c, generatedAt)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// WriteHTML renders the report as a standalone HTML document.
func WriteHTML(w io.Writer, c *Case, generatedAt time.Time) error {
	doc, err := BuildReport(c, generatedAt)
	if err != nil {
		return err
	}
	tmpl, err := template.New("report").Funcs(templateFuncs).Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("forensics: report template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, doc); err != nil {
		return fmt.Errorf("forensics: report template: %w", err)
	}
	_, err = w.Write(buf.Bytes())
	return err
}

// templateFuncs keeps the template honest about values it cannot format
// itself: an empty timestamp is "not recorded", never "0001-01-01 00:00:00".
var templateFuncs = template.FuncMap{
	"when": func(t time.Time) string {
		if t.IsZero() {
			return "not recorded"
		}
		return t.UTC().Format("2006-01-02 15:04:05 UTC")
	},
	"whenISO": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	},
	"short": func(s string) string {
		if len(s) <= 16 {
			return s
		}
		return s[:16] + "…"
	},
	"size": func(n int64) string {
		switch {
		case n >= 1<<30:
			return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30))
		case n >= 1<<20:
			return fmt.Sprintf("%.2f MiB", float64(n)/(1<<20))
		case n >= 1<<10:
			return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
		default:
			return fmt.Sprintf("%d B", n)
		}
	},
}
