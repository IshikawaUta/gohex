package service

import (
	"crypto/sha256"
	"encoding/csv"
	stdhex "encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/browser"
)

// The artefact kinds BrowserExport accepts. They match the field names of
// browser.Report so a caller can predict them without reading the source.
const (
	browserKindHistory   = "history"
	browserKindDownloads = "downloads"
	browserKindBookmarks = "bookmarks"
	browserFormatCSV     = "csv"
	browserFormatJSON    = "json"
)

// BrowserProfiles lists the browser profiles installed below home. An empty
// home means the current user's own home directory. Listing reads directory
// names only: no browser database is opened, so this needs no audit record.
func (a *App) BrowserProfiles(home string) ([]browser.Profile, error) {
	return browser.Discover(home)
}

// BrowserRead extracts the history, downloads and bookmarks of one profile.
// The databases are opened read-only and a write-ahead log is interpreted
// rather than checkpointed, so the evidence is left exactly as found. The
// access itself is recorded in the audit log.
func (a *App) BrowserRead(p browser.Profile) (browser.Report, error) {
	if strings.TrimSpace(p.Dir) == "" {
		return browser.Report{}, errors.New("service: browser: empty profile directory")
	}
	dir := absPath(p.Dir)
	report, err := browser.Read(browser.Profile{Browser: p.Browser, Name: p.Name, Dir: dir})
	if err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionOpen,
			Target: dir,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "browser", "browser": p.Browser.String(), "error": err.Error()},
		})
		return browser.Report{}, err
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionOpen,
		Target: dir,
		Result: audit.ResultOK,
		Detail: map[string]string{
			"op":        "browser",
			"browser":   p.Browser.String(),
			"profile":   p.Name,
			"history":   strconv.Itoa(len(report.History)),
			"downloads": strconv.Itoa(len(report.Downloads)),
			"bookmarks": strconv.Itoa(len(report.Bookmarks)),
			"warnings":  strconv.Itoa(len(report.Warnings)),
		},
	})
	return report, nil
}

// BrowserExport re-reads a profile and writes one of its artefacts to
// dstPath, which must not already exist. The file is hashed and both the
// successful and the failed export are recorded in the audit log, so a report
// produced from this tool carries a verifiable fingerprint.
func (a *App) BrowserExport(p browser.Profile, kind, format, dstPath string) (SaveResult, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	format = strings.ToLower(strings.TrimSpace(format))
	if dstPath == "" {
		return SaveResult{}, errors.New("service: browser export: empty destination")
	}
	if format != browserFormatCSV && format != browserFormatJSON {
		return SaveResult{}, fmt.Errorf("service: browser export: unknown format %q", format)
	}

	report, err := browserArtifactReport(a, p, kind)
	if err != nil {
		return SaveResult{}, err
	}

	var payload []byte
	if format == browserFormatJSON {
		payload, err = json.MarshalIndent(browserExportDoc{
			ExportedAt: time.Now().UTC(),
			Source:     report.Profile.Dir,
			Browser:    report.Profile.Browser.String(),
			Profile:    report.Profile.Name,
			Kind:       kind,
			Warnings:   report.Warnings,
			Items:      browserItems(report, kind),
		}, "", "  ")
		payload = append(payload, '\n')
	} else {
		payload, err = marshalBrowserCSV(report, kind)
	}
	if err != nil {
		return SaveResult{}, err
	}

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return SaveResult{}, fmt.Errorf("service: browser export: %w", err)
	}
	abort := func(err error) (SaveResult, error) {
		dst.Close()
		os.Remove(dstPath)
		_ = a.log.Log(audit.Event{
			Action: audit.ActionExport,
			Target: report.Profile.Dir,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "browser", "kind": kind, "dest": dstPath, "error": err.Error()},
		})
		return SaveResult{}, err
	}

	h := sha256.New()
	h.Write(payload)
	n, err := dst.Write(payload)
	if err != nil {
		return abort(fmt.Errorf("service: browser export: %w", err))
	}
	if err := dst.Close(); err != nil {
		return abort(fmt.Errorf("service: browser export close: %w", err))
	}

	sum := stdhex.EncodeToString(h.Sum(nil))
	_ = a.log.Log(audit.Event{
		Action: audit.ActionExport,
		Target: report.Profile.Dir,
		Result: audit.ResultOK,
		Hash:   "sha256:" + sum,
		Detail: map[string]string{
			"op":     "browser",
			"kind":   kind,
			"format": format,
			"dest":   dstPath,
			"items":  strconv.Itoa(browserCount(report, kind)),
			"bytes":  strconv.Itoa(n),
		},
	})
	return SaveResult{
		Path:       dstPath,
		BytesSaved: int64(n),
		Mode:       "browser_" + kind,
		SHA256:     sum,
	}, nil
}

// browserArtifactReport reads a profile and keeps only the requested
// artefact. Splitting it out lets the export path validate the kind before
// touching the disk without duplicating the read logic.
func browserArtifactReport(a *App, p browser.Profile, kind string) (browser.Report, error) {
	if kind != browserKindHistory && kind != browserKindDownloads && kind != browserKindBookmarks {
		return browser.Report{}, fmt.Errorf("service: browser export: unknown artefact %q", kind)
	}
	report, err := a.BrowserRead(p)
	if err != nil {
		return browser.Report{}, err
	}
	switch kind {
	case browserKindHistory:
		report.Downloads, report.Bookmarks = nil, nil
	case browserKindDownloads:
		report.History, report.Bookmarks = nil, nil
	case browserKindBookmarks:
		report.History, report.Downloads = nil, nil
	}
	return report, nil
}

// browserItems returns the artefact slice as its own dynamic type, which is
// what json.Marshal needs to emit the concrete element struct.
func browserItems(r browser.Report, kind string) any {
	switch kind {
	case browserKindHistory:
		return r.History
	case browserKindDownloads:
		return r.Downloads
	default:
		return r.Bookmarks
	}
}

func browserCount(r browser.Report, kind string) int {
	switch kind {
	case browserKindHistory:
		return len(r.History)
	case browserKindDownloads:
		return len(r.Downloads)
	default:
		return len(r.Bookmarks)
	}
}

// browserExportDoc is the JSON envelope: a bare array would lose which
// profile and which artefact produced it, and a report without provenance is
// not much use as evidence.
type browserExportDoc struct {
	ExportedAt time.Time `json:"exportedAt"`
	Source     string    `json:"source"`
	Browser    string    `json:"browser"`
	Profile    string    `json:"profile"`
	Kind       string    `json:"kind"`
	Warnings   []string  `json:"warnings,omitempty"`
	Items      any       `json:"items"`
}

// csvTime renders a timestamp as RFC 3339 in UTC, leaving an unset time
// empty rather than printing Go's zero value, which no tool would recognise.
func csvTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// marshalBrowserCSV flattens one artefact into a table with a header row.
// Each column name is the field a report reader would search for, so the
// file can be dropped straight into a spreadsheet or a dataframe.
func marshalBrowserCSV(r browser.Report, kind string) ([]byte, error) {
	var header []string
	var rows [][]string
	switch kind {
	case browserKindHistory:
		header = []string{"url", "title", "visits", "typed", "lastVisit"}
		for _, e := range r.History {
			rows = append(rows, []string{
				e.URL, e.Title, strconv.FormatInt(e.Visits, 10),
				strconv.FormatInt(e.Typed, 10), csvTime(e.LastVisit),
			})
		}
	case browserKindDownloads:
		header = []string{"url", "target", "start", "end", "receivedBytes",
			"totalBytes", "state", "status"}
		for _, d := range r.Downloads {
			rows = append(rows, []string{
				d.URL, d.Target, csvTime(d.Start), csvTime(d.End),
				strconv.FormatInt(d.Received, 10), strconv.FormatInt(d.Total, 10),
				strconv.Itoa(d.State), d.Status,
			})
		}
	case browserKindBookmarks:
		header = []string{"path", "title", "kind", "url", "added"}
		for _, b := range r.Bookmarks {
			rows = append(rows, []string{
				b.Path, b.Title, b.Kind.String(), b.URL, csvTime(b.Added),
			})
		}
	default:
		return nil, fmt.Errorf("service: browser export: unknown artefact %q", kind)
	}

	var sb strings.Builder
	w := csv.NewWriter(&sb)
	if err := w.Write(header); err != nil {
		return nil, fmt.Errorf("service: browser export: %w", err)
	}
	if err := w.WriteAll(rows); err != nil {
		return nil, fmt.Errorf("service: browser export: %w", err)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("service: browser export: %w", err)
	}
	return []byte(sb.String()), nil
}
