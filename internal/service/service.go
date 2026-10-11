// Package service is the application layer between the GUI/CLI front-ends and
// the GoHex engines. It owns documents, enforces the security policy
// (read-only profile, three-gate disk writes, sandbox mode), and records
// audit events for every open/save/export action.
package service

import (
	"bytes"
	"crypto/sha256"
	stdhex "encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/config"
	"github.com/IshikawaUta/gohex/internal/core"
	encoding "github.com/IshikawaUta/gohex/internal/encoding" // package bincoding
	"github.com/IshikawaUta/gohex/internal/forensics"
	"github.com/IshikawaUta/gohex/internal/fs"
	"github.com/IshikawaUta/gohex/internal/fusefs"
	"github.com/IshikawaUta/gohex/internal/hash"
	"github.com/IshikawaUta/gohex/internal/hex"
	"github.com/IshikawaUta/gohex/internal/image"
	"github.com/IshikawaUta/gohex/pkg/version"
)

// maxReadWindow caps a single ReadWindow request (1 MiB) — enough for any
// visible viewport, never enough to exhaust memory.
const maxReadWindow = 1 << 20

// maxHashAuditSize: saves at or below this size get an automatic SHA-256 in
// the audit record; larger files hash on demand via the checksum panel.
const maxHashAuditSize = 64 << 20

// Emitter receives UI notifications (implemented by the Wails runtime hub;
// nil is allowed for headless/CLI use).
type Emitter interface {
	Emit(event string, payload any)
}

// DocInfo is the JSON-serialisable snapshot of an open document.
type DocInfo struct {
	ID             int64  `json:"id"`
	Path           string `json:"path"`
	Name           string `json:"name"`
	Size           int64  `json:"size"`
	BaseSize       int64  `json:"baseSize"`
	Dirty          bool   `json:"dirty"`
	OverwriteOnly  bool   `json:"overwriteOnly"`
	Version        uint64 `json:"version"`
	CanUndo        bool   `json:"canUndo"`
	UndoLabel      string `json:"undoLabel,omitempty"`
	CanRedo        bool   `json:"canRedo"`
	RedoLabel      string `json:"redoLabel,omitempty"`
	SelStart       int64  `json:"selStart"`
	SelEnd         int64  `json:"selEnd"`
	Cursor         int64  `json:"cursor"`
	Encoding       string `json:"encoding"`
	Profile        string `json:"profile"`
	EditingAllowed bool   `json:"editingAllowed"`
}

// WindowData is one viewport slice: raw bytes plus the decoded text column.
type WindowData struct {
	Offset int64  `json:"offset"`
	Bytes  []byte `json:"bytes"`
	Text   string `json:"text"`
}

// FindRequest describes one search operation. Max > 0 means "find all up to
// Max"; Max <= 0 means "find the single nearest match" honouring Direction
// and Wrap.
type FindRequest struct {
	ID        int64  `json:"id"`
	Mode      string `json:"mode"` // hex | text | regex
	Pattern   string `json:"pattern"`
	Encoding  string `json:"encoding"`
	CaseFold  bool   `json:"caseFold"`
	Direction string `json:"direction"` // next | prev
	From      int64  `json:"from"`      // cursor position
	Wrap      bool   `json:"wrap"`
	Max       int    `json:"max"`
}

// FindResponse carries search hits (ascending by offset).
type FindResponse struct {
	Matches   []hex.Match `json:"matches"`
	Count     int         `json:"count"`
	Truncated bool        `json:"truncated"`
}

// SaveResult reports what a save operation did.
type SaveResult struct {
	Path       string `json:"path"`
	BytesSaved int64  `json:"bytesSaved"`
	Mode       string `json:"mode"` // in-place | rewrite | sandbox
	SHA256     string `json:"sha256,omitempty"`
}

// FileInfo is a minimal file-attribute view.
type FileInfo struct {
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"modTime"`
	IsDir   bool      `json:"isDir"`
}

// doc is one open buffer. mu guards the mutable session fields (selection,
// cursor, encoding, path, last pattern); the document has its own lock.
type doc struct {
	mu       sync.Mutex
	id       int64
	document *hex.Document
	src      core.Source // owned by the service; closed on CloseDocument
	path     string
	selStart int64
	selEnd   int64
	cursor   int64
	enc      encoding.Encoding
	lastFind *hex.Pattern
}

// fsSession is an open, read-only view of a filesystem inside an image.
// Sessions are cached so repeated directory listings do not re-parse the
// superblock, and are released when the App closes.
type fsSession struct {
	r image.Reader
	f fs.FS
}

// App is the bound API of GoHex. All methods are safe for concurrent use.
type App struct {
	mu      sync.Mutex
	cfg     config.Preferences
	cfgPath string
	log     *audit.Logger
	docs    map[int64]*doc
	order   []int64
	nextID  int64
	emit    Emitter
	fss     map[string]*fsSession

	// The open forensic case, if any. It is replaced wholesale and guarded
	// by mu; the heavy work (hashing evidence) happens outside the lock.
	curCase  *forensics.Case
	casePath string

	startupSkipDisclaimer bool
	startupFiles          []string

	// Async disk-clone jobs. cloneSeq hands out job ids; clones keeps
	// the live set (a job is retained after completion so its final
	// status can still be queried).
	cloneSeq int64
	clones   map[int64]*cloneJob

	// Active FUSE mounts (Linux only). Keyed by mountpoint; value keeps
	// the evidence source path for audit/list purposes.
	mounts map[string]mountEntry
}

type mountEntry struct {
	h   fusefs.Handle
	src string
}

// New builds the application service: loads preferences (missing file → safe
// defaults), applies GOHEX_* environment overlays and opens the audit log.
// cfgPath may be empty to use the per-user default location.
func New(cfgPath string, emitter Emitter) (*App, error) {
	if cfgPath == "" {
		cfgPath = config.DefaultPath()
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		// Corrupt config: fall back to safe defaults rather than trusting a
		// possibly tampered policy file.
		cfg = config.Default()
	}
	cfg.ApplyEnv()
	if verr := cfg.Validate(); verr != nil {
		cfg = config.Default()
		cfg.ApplyEnv()
	}
	if dir := filepath.Dir(cfg.AuditLogPath); dir != "" {
		if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
			cfg.AuditLogPath = ""
		}
	}
	log, err := audit.Open(cfg.AuditLogPath, nil)
	if err != nil {
		log = audit.Noop()
	}
	return &App{
		cfg:     cfg,
		cfgPath: cfgPath,
		log:     log,
		docs:    make(map[int64]*doc),
		fss:     make(map[string]*fsSession),
		emit:    emitter,
		mounts:  make(map[string]mountEntry),
	}, nil
}

// Close releases service resources: open documents and the audit log.
func (a *App) Close() error {
	// Detach FUSE mounts before tearing down: the kernel must not be
	// left pointing at a dead daemon.
	a.ShutdownUnmounts()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, d := range a.docs {
		d.document.Close()
		if d.src != nil {
			d.src.Close()
		}
	}
	a.docs = nil
	a.order = nil
	for _, s := range a.fss {
		s.r.Close()
	}
	a.fss = nil
	if a.log != nil {
		return a.log.Close()
	}
	return nil
}

func (a *App) event(name string, payload any) {
	if a.emit != nil {
		a.emit.Emit(name, payload)
	}
}

// Version returns the application version.
func (a *App) Version() string { return version.Version }

// ShortcutDefaults returns the stock keymap (action ID → chord) backing
// the Preferences shortcuts editor and its reset button.
func (a *App) ShortcutDefaults() map[string]string { return config.DefaultShortcuts() }

// Preferences returns a copy of the active configuration.
func (a *App) Preferences() config.Preferences {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg
}

// SetPreferences validates and persists configuration changes, recording
// security-relevant changes in the audit log.
func (a *App) SetPreferences(p config.Preferences) error {
	if err := p.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	prev := a.cfg
	a.cfg = p
	a.mu.Unlock()
	if err := p.Save(a.cfgPath); err != nil {
		a.mu.Lock()
		a.cfg = prev
		a.mu.Unlock()
		return err
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionConfig,
		Target: a.cfgPath,
		Result: audit.ResultOK,
		Detail: map[string]string{
			"profile": p.Profile,
			"theme":   string(p.Theme),
			"unsafe":  fmt.Sprintf("%t", p.AllowUnsafeWrite),
		},
	})
	a.event("config:changed", nil)
	return nil
}

// Translate localises a UI string.
func (a *App) Translate(lang, key string, args ...any) string {
	return config.T(lang, key, args...)
}

// StartupInfo carries GUI startup hints: files to open from the command line
// and whether the first-run disclaimer was pre-accepted (automation/tests).
type StartupInfo struct {
	SkipDisclaimer bool     `json:"skipDisclaimer"`
	Files          []string `json:"files"`
}

// SetStartupHints records command-line/env hints before the UI starts.
func (a *App) SetStartupHints(skipDisclaimer bool, files []string) {
	a.mu.Lock()
	a.startupSkipDisclaimer = skipDisclaimer
	a.startupFiles = files
	a.mu.Unlock()
}

// StartupInfo returns the hints recorded by SetStartupHints.
func (a *App) StartupInfo() StartupInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	files := make([]string, len(a.startupFiles))
	copy(files, a.startupFiles)
	return StartupInfo{SkipDisclaimer: a.startupSkipDisclaimer, Files: files}
}

// Catalog returns the full UI translation catalog for lang ("en" or "id"),
// letting the frontend translate synchronously after a single fetch.
func (a *App) Catalog(lang string) map[string]string {
	return config.Catalog(lang)
}

// Disclaimer returns the localised legal disclaimer for splash/About dialogs.
func (a *App) Disclaimer() string {
	a.mu.Lock()
	lang := a.cfg.Language
	a.mu.Unlock()
	return config.T(lang, "dialog.disclaimer.body")
}

// EditingAllowed reports whether the current profile permits edits.
func (a *App) EditingAllowed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.EditingAllowed()
}

// --- documents ---------------------------------------------------------

// OpenFile opens path read-only (memory-mapped when safe) as a new tab.
func (a *App) OpenFile(path string) (DocInfo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	src, err := core.Open(abs, 0)
	if err != nil {
		return DocInfo{}, fmt.Errorf("open %q: %w", path, err)
	}
	d := &doc{
		document: hex.New(src),
		path:     abs,
		src:      src,
		enc:      encoding.ASCII,
	}
	a.mu.Lock()
	a.nextID++
	d.id = a.nextID
	a.docs[d.id] = d
	a.order = append(a.order, d.id)
	a.cfg.AddRecent(abs)
	size := src.Size()
	a.mu.Unlock()
	_ = a.log.Log(audit.Event{
		Action: audit.ActionOpen,
		Target: abs,
		Result: audit.ResultOK,
		Detail: map[string]string{"size": fmt.Sprintf("%d", size), "mode": "read-only"},
	})
	a.event("docs:changed", nil)
	return a.DocumentInfo(d.id)
}

// NewDocument creates an empty untitled buffer.
func (a *App) NewDocument() DocInfo {
	d := &doc{document: hex.NewEmpty(), enc: encoding.ASCII}
	a.mu.Lock()
	a.nextID++
	d.id = a.nextID
	a.docs[d.id] = d
	a.order = append(a.order, d.id)
	a.mu.Unlock()
	a.event("docs:changed", nil)
	info, _ := a.DocumentInfo(d.id)
	return info
}

// CloseDocument closes a tab, releasing its source.
func (a *App) CloseDocument(id int64) error {
	a.mu.Lock()
	d, ok := a.docs[id]
	if ok {
		delete(a.docs, id)
		for i, v := range a.order {
			if v == id {
				a.order = append(a.order[:i], a.order[i+1:]...)
				break
			}
		}
	}
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("service: no document %d", id)
	}
	d.document.Close()
	if d.src != nil {
		d.src.Close()
	}
	a.event("docs:changed", nil)
	return nil
}

// ListDocuments returns snapshots of open documents in open order.
func (a *App) ListDocuments() []DocInfo {
	a.mu.Lock()
	ids := append([]int64(nil), a.order...)
	a.mu.Unlock()
	out := make([]DocInfo, 0, len(ids))
	for _, id := range ids {
		info, err := a.DocumentInfo(id)
		if err == nil {
			out = append(out, info)
		}
	}
	return out
}

// DocumentInfo returns a snapshot of one document.
func (a *App) DocumentInfo(id int64) (DocInfo, error) {
	d, err := a.lookup(id)
	if err != nil {
		return DocInfo{}, err
	}
	undoLabel, canUndo := d.document.CanUndo()
	redoLabel, canRedo := d.document.CanRedo()
	a.mu.Lock()
	prof := a.cfg.Profile
	editing := a.cfg.EditingAllowed()
	a.mu.Unlock()
	d.mu.Lock()
	selStart, selEnd, cursor := d.selStart, d.selEnd, d.cursor
	enc := d.enc.String()
	path := d.path
	d.mu.Unlock()
	name := path
	if name == "" {
		name = fmt.Sprintf("Untitled-%d", id)
	} else {
		name = filepath.Base(path)
	}
	return DocInfo{
		ID:             id,
		Path:           path,
		Name:           name,
		Size:           d.document.Size(),
		BaseSize:       d.document.BaseSize(),
		Dirty:          d.document.Dirty(),
		OverwriteOnly:  d.document.OverwriteOnly(),
		Version:        d.document.Version(),
		CanUndo:        canUndo,
		UndoLabel:      undoLabel,
		CanRedo:        canRedo,
		RedoLabel:      redoLabel,
		SelStart:       selStart,
		SelEnd:         selEnd,
		Cursor:         cursor,
		Encoding:       enc,
		Profile:        prof,
		EditingAllowed: editing,
	}, nil
}

func (a *App) lookup(id int64) (*doc, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, ok := a.docs[id]
	if !ok {
		return nil, fmt.Errorf("service: no document %d", id)
	}
	return d, nil
}

// ReadWindow returns up to length bytes at offset together with the decoded
// text column (for the visible viewport only — the grid is virtual).
func (a *App) ReadWindow(id int64, offset, length int64) (WindowData, error) {
	d, err := a.lookup(id)
	if err != nil {
		return WindowData{}, err
	}
	if offset < 0 {
		return WindowData{}, core.ErrNegativeOffset
	}
	if length <= 0 || length > maxReadWindow {
		length = maxReadWindow
	}
	size := d.document.Size()
	if offset >= size {
		return WindowData{Offset: offset, Bytes: []byte{}, Text: ""}, nil
	}
	if offset+length > size {
		length = size - offset
	}
	buf := make([]byte, length)
	n, err := d.document.ReadAt(buf, offset)
	if n == 0 && err != nil && !errors.Is(err, io.EOF) {
		return WindowData{}, fmt.Errorf("service: read: %w", err)
	}
	buf = buf[:n]
	d.mu.Lock()
	enc := d.enc
	d.mu.Unlock()
	return WindowData{
		Offset: offset,
		Bytes:  buf,
		Text:   encoding.ColumnText(enc, buf),
	}, nil
}

// SetSelection updates selection and cursor for a document.
func (a *App) SetSelection(id int64, start, end int64) error {
	d, err := a.lookup(id)
	if err != nil {
		return err
	}
	if start < 0 {
		start = 0
	}
	if end < start {
		start, end = end, start
	}
	size := d.document.Size()
	if start > size {
		start = size
	}
	if end > size {
		end = size
	}
	d.mu.Lock()
	d.selStart, d.selEnd, d.cursor = start, end, start
	d.mu.Unlock()
	return nil
}

// Goto resolves an offset expression (hex/dec/relative/sector) against the
// document and moves the cursor there.
func (a *App) Goto(id int64, expr string) (int64, error) {
	d, err := a.lookup(id)
	if err != nil {
		return 0, err
	}
	d.mu.Lock()
	ref := d.cursor
	d.mu.Unlock()
	a.mu.Lock()
	base := core.BaseHex
	if a.cfg.OffsetRadix == "dec" {
		base = core.BaseDec
	}
	a.mu.Unlock()
	off, err := core.ParseOffset(expr, base, ref, 512)
	if err != nil {
		return 0, err
	}
	if size := d.document.Size(); off > size {
		off = size
	}
	d.mu.Lock()
	d.cursor = off
	d.selStart, d.selEnd = off, off
	d.mu.Unlock()
	return off, nil
}

// SetEncoding switches the text column encoding for a document.
func (a *App) SetEncoding(id int64, name string) error {
	d, err := a.lookup(id)
	if err != nil {
		return err
	}
	enc, err := encoding.ParseEncoding(name)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.enc = enc
	d.mu.Unlock()
	return nil
}

// --- editing -----------------------------------------------------------

func (a *App) guardEdit() error {
	a.mu.Lock()
	allowed := a.cfg.EditingAllowed()
	a.mu.Unlock()
	if !allowed {
		return errors.New("service: editing is disabled in the read-only profile")
	}
	return nil
}

// WriteBytes overwrites bytes at offset (in-place overwrite).
func (a *App) WriteBytes(id int64, offset int64, data []byte) error {
	if err := a.guardEdit(); err != nil {
		return err
	}
	d, err := a.lookup(id)
	if err != nil {
		return err
	}
	if err := d.document.Overwrite(offset, data); err != nil {
		return err
	}
	a.event("doc:changed", id)
	return nil
}

// InsertBytes splices data into the document at offset.
func (a *App) InsertBytes(id int64, offset int64, data []byte) error {
	if err := a.guardEdit(); err != nil {
		return err
	}
	d, err := a.lookup(id)
	if err != nil {
		return err
	}
	if err := d.document.Insert(offset, data); err != nil {
		return err
	}
	a.event("doc:changed", id)
	return nil
}

// DeleteRange removes length bytes at offset.
func (a *App) DeleteRange(id int64, offset, length int64) error {
	if err := a.guardEdit(); err != nil {
		return err
	}
	d, err := a.lookup(id)
	if err != nil {
		return err
	}
	if err := d.document.Delete(offset, length); err != nil {
		return err
	}
	a.event("doc:changed", id)
	return nil
}

// FillRange overwrites the range with a repeated byte value.
func (a *App) FillRange(id int64, offset, length int64, value byte) error {
	if err := a.guardEdit(); err != nil {
		return err
	}
	d, err := a.lookup(id)
	if err != nil {
		return err
	}
	if err := d.document.Fill(offset, length, value); err != nil {
		return err
	}
	a.event("doc:changed", id)
	return nil
}

// Undo reverts the last edit and returns its label.
func (a *App) Undo(id int64) (string, error) {
	if err := a.guardEdit(); err != nil {
		return "", err
	}
	d, err := a.lookup(id)
	if err != nil {
		return "", err
	}
	label, err := d.document.Undo()
	if err == nil {
		a.event("doc:changed", id)
	}
	return label, err
}

// Redo re-applies the last undone edit.
func (a *App) Redo(id int64) (string, error) {
	if err := a.guardEdit(); err != nil {
		return "", err
	}
	d, err := a.lookup(id)
	if err != nil {
		return "", err
	}
	label, err := d.document.Redo()
	if err == nil {
		a.event("doc:changed", id)
	}
	return label, err
}

// --- search ------------------------------------------------------------

// Find locates matches for a pattern. With Max > 0 it returns up to Max
// matches (find-all); with Max <= 0 it returns the single nearest match
// honouring Direction and Wrap.
func (a *App) Find(req FindRequest) (FindResponse, error) {
	d, err := a.lookup(req.ID)
	if err != nil {
		return FindResponse{}, err
	}
	p, err := a.compilePattern(req)
	if err != nil {
		return FindResponse{}, err
	}
	d.mu.Lock()
	d.lastFind = p
	d.mu.Unlock()

	size := d.document.Size()
	from := clampFrom(req.From, size)

	if req.Max > 0 { // find-all within [from, size) or [0, from) for prev
		var hits []hex.Match
		lo, hi := from, size
		if req.Direction == "prev" {
			lo, hi = 0, from
		}
		hits, err = hex.FindAll(d.document, p, lo, hi, req.Max)
		if err != nil {
			return FindResponse{}, err
		}
		return FindResponse{Matches: hits, Count: len(hits), Truncated: len(hits) >= req.Max}, nil
	}

	// Single nearest match.
	if req.Direction == "prev" {
		m, err := hex.FindPrev(d.document, p, from, 0)
		if err != nil {
			return FindResponse{}, err
		}
		if m == nil && req.Wrap && from < size {
			m, err = hex.FindPrev(d.document, p, size, from)
			if err != nil {
				return FindResponse{}, err
			}
		}
		if m == nil {
			return FindResponse{}, nil
		}
		return FindResponse{Matches: []hex.Match{*m}, Count: 1}, nil
	}
	m, err := hex.FindNext(d.document, p, from)
	if err != nil {
		return FindResponse{}, err
	}
	if m == nil && req.Wrap && from > 0 {
		m, err = hex.FindNext(d.document, p, 0)
		if err != nil {
			return FindResponse{}, err
		}
	}
	if m == nil {
		return FindResponse{}, nil
	}
	return FindResponse{Matches: []hex.Match{*m}, Count: 1}, nil
}

func clampFrom(from, size int64) int64 {
	if from < 0 {
		return 0
	}
	if from > size {
		return size
	}
	return from
}

func (a *App) compilePattern(req FindRequest) (*hex.Pattern, error) {
	switch req.Mode {
	case "hex", "":
		return hex.ParseHexPattern(req.Pattern)
	case "text":
		enc := encoding.ASCII
		if req.Encoding != "" {
			var err error
			enc, err = encoding.ParseEncoding(req.Encoding)
			if err != nil {
				return nil, err
			}
		}
		return hex.NewTextPattern(req.Pattern, enc, req.CaseFold)
	case "regex":
		return hex.NewRegexPattern(req.Pattern)
	}
	return nil, fmt.Errorf("service: unknown search mode %q", req.Mode)
}

// ReplaceAll replaces every match. confirmed must be true — the GUI shows a
// confirmation dialog first; bulk edits are never applied silently.
func (a *App) ReplaceAll(id int64, mode, pattern, replacement, encName string, caseFold bool, confirmed bool) (int, error) {
	if err := a.guardEdit(); err != nil {
		return 0, err
	}
	if !confirmed {
		return 0, errors.New("service: replace requires explicit confirmation")
	}
	d, err := a.lookup(id)
	if err != nil {
		return 0, err
	}
	p, err := a.compilePattern(FindRequest{Mode: mode, Pattern: pattern, Encoding: encName, CaseFold: caseFold})
	if err != nil {
		return 0, err
	}
	enc := encoding.ASCII
	if encName != "" {
		if enc, err = encoding.ParseEncoding(encName); err != nil {
			return 0, err
		}
	}
	var repl []byte
	if mode == "text" {
		repl = encoding.Encode(enc, replacement)
	} else {
		repl, err = encoding.HexToBytes(replacement)
		if err != nil {
			return 0, fmt.Errorf("service: replacement: %w", err)
		}
	}
	n, err := d.document.ReplaceAll(p, repl, 0)
	if err == nil {
		a.event("doc:changed", id)
	}
	return n, err
}

// --- save --------------------------------------------------------------

// Save writes the document back to its path:
//
//   - read-only profile → denied (audited)
//   - sandbox mode → simulated (audited, no disk change)
//   - overwrite-only edits → in-place writes of the changed ranges
//   - structural edits → atomic full rewrite via temp file + rename
//
// Documents without a path must use SaveAs.
func (a *App) Save(id int64) (SaveResult, error) {
	if err := a.guardEdit(); err != nil {
		return SaveResult{}, err
	}
	d, err := a.lookup(id)
	if err != nil {
		return SaveResult{}, err
	}
	d.mu.Lock()
	path := d.path
	d.mu.Unlock()
	if path == "" {
		return SaveResult{}, errors.New("service: document has no path; use Save As")
	}
	a.mu.Lock()
	sandbox := a.cfg.SandboxMode
	a.mu.Unlock()
	if sandbox {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionSave, Target: path, Result: audit.ResultOK,
			Detail: map[string]string{"sandbox": "true"},
		})
		return SaveResult{Path: path, Mode: "sandbox"}, nil
	}

	var res SaveResult
	ranges, full := d.document.DirtyState()
	switch {
	case !d.document.Dirty():
		res = SaveResult{Path: path, Mode: "in-place"}
	case !full:
		res, err = a.saveInPlace(d, path, ranges)
	default:
		res, err = a.rewriteFile(d, path)
	}
	if err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionSave, Target: path, Result: audit.ResultError,
			Detail: map[string]string{"error": err.Error()},
		})
		return SaveResult{}, err
	}
	d.document.MarkSaved()
	detail := map[string]string{
		"mode":  res.Mode,
		"bytes": fmt.Sprintf("%d", res.BytesSaved),
	}
	if d.document.BaseSize() <= maxHashAuditSize && res.Mode != "sandbox" {
		if sum, herr := a.hashFileSHA256(path); herr == nil {
			res.SHA256 = sum
			detail["sha256"] = sum
		}
	}
	_ = a.log.Log(audit.Event{Action: audit.ActionSave, Target: path, Result: audit.ResultOK, Detail: detail})
	a.event("doc:saved", id)
	return res, nil
}

// SaveAs writes the document to newPath and rebinds the document to it.
func (a *App) SaveAs(id int64, newPath string) (SaveResult, error) {
	if err := a.guardEdit(); err != nil {
		return SaveResult{}, err
	}
	d, err := a.lookup(id)
	if err != nil {
		return SaveResult{}, err
	}
	abs, err := filepath.Abs(newPath)
	if err != nil {
		abs = newPath
	}
	a.mu.Lock()
	sandbox := a.cfg.SandboxMode
	a.mu.Unlock()
	if sandbox {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionSaveAs, Target: abs, Result: audit.ResultOK,
			Detail: map[string]string{"sandbox": "true"},
		})
		return SaveResult{Path: abs, Mode: "sandbox"}, nil
	}
	written, err := streamToFile(d.document, abs, 0o644)
	if err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionSaveAs, Target: abs, Result: audit.ResultError,
			Detail: map[string]string{"error": err.Error()},
		})
		return SaveResult{}, err
	}
	res := SaveResult{Path: abs, BytesSaved: written, Mode: "rewrite"}
	if written <= maxHashAuditSize {
		if sum, herr := a.hashFileSHA256(abs); herr == nil {
			res.SHA256 = sum
		}
	}
	d.document.MarkSaved()
	d.mu.Lock()
	d.path = abs
	d.mu.Unlock()
	_ = a.log.Log(audit.Event{
		Action: audit.ActionSaveAs, Target: abs, Result: audit.ResultOK,
		Detail: map[string]string{"bytes": fmt.Sprintf("%d", written)},
	})
	a.event("doc:saved", id)
	return res, nil
}

func (a *App) saveInPlace(d *doc, path string, ranges []hex.DirtyRange) (SaveResult, error) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // writing back the user's own file
	if err != nil {
		return SaveResult{}, fmt.Errorf("service: open for write: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return SaveResult{}, err
	}
	// Guard against external truncation/extension of the evidence file.
	if st.Size() != d.document.BaseSize() {
		return a.rewriteFile(d, path)
	}
	var written int64
	for _, r := range ranges {
		buf, err := d.document.ReadCopy(r.Start, r.Length)
		if err != nil {
			return SaveResult{}, fmt.Errorf("service: read range: %w", err)
		}
		n, err := f.WriteAt(buf, r.Start)
		written += int64(n)
		if err != nil {
			return SaveResult{}, fmt.Errorf("service: write range: %w", err)
		}
	}
	if err := f.Sync(); err != nil {
		return SaveResult{}, fmt.Errorf("service: sync: %w", err)
	}
	return SaveResult{Path: path, BytesSaved: written, Mode: "in-place"}, nil
}

func (a *App) rewriteFile(d *doc, path string) (SaveResult, error) {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	written, err := streamToFile(d.document, path, mode)
	if err != nil {
		return SaveResult{}, err
	}
	return SaveResult{Path: path, BytesSaved: written, Mode: "rewrite"}, nil
}

// streamToFile writes the document to path atomically: temp file in the same
// directory, fsync, chmod, rename over the target.
func streamToFile(doc *hex.Document, path string, mode os.FileMode) (int64, error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".gohex-save-*")
	if err != nil {
		return 0, fmt.Errorf("service: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	n, err := doc.WriteTo(tmp)
	if err != nil {
		tmp.Close()
		return 0, fmt.Errorf("service: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return 0, fmt.Errorf("service: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return 0, fmt.Errorf("service: chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return 0, fmt.Errorf("service: rename: %w", err)
	}
	return n, nil
}

func (a *App) hashFileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return stdhex.EncodeToString(h.Sum(nil)), nil
}

// --- hashing, metadata, conversion -------------------------------------

// HashDocument computes a digest of the whole document or the selection.
// The result is recorded in the audit log (chain of custody).
func (a *App) HashDocument(id int64, algo string, selectionOnly bool) (string, error) {
	d, err := a.lookup(id)
	if err != nil {
		return "", err
	}
	alg, err := hash.Parse(algo)
	if err != nil {
		return "", err
	}
	var r io.Reader
	scope := "document"
	if selectionOnly {
		d.mu.Lock()
		selStart, selEnd := d.selStart, d.selEnd
		d.mu.Unlock()
		if selEnd <= selStart {
			return "", errors.New("service: empty selection")
		}
		buf, err := d.document.ReadCopy(selStart, selEnd-selStart)
		if err != nil {
			return "", err
		}
		r = bytes.NewReader(buf)
		scope = "selection"
	} else {
		pr, pw := io.Pipe()
		go func() {
			_, err := d.document.WriteTo(pw)
			pw.CloseWithError(err)
		}()
		r = pr
	}
	sum, err := hash.Reader(alg, r, func(total int64) bool {
		a.event("progress", map[string]any{"op": "hash", "done": total})
		return true
	})
	if err != nil {
		return "", err
	}
	target := d.document.Path()
	_ = a.log.Log(audit.Event{
		Action: audit.ActionHashVerify,
		Target: target,
		Result: audit.ResultOK,
		Hash:   hash.Format(alg, sum, true),
		Detail: map[string]string{"scope": scope},
	})
	return hash.Format(alg, sum, true), nil
}

// Stat returns basic file attributes (attributes viewer).
func (a *App) Stat(path string) (FileInfo, error) {
	st, err := os.Stat(path) //nolint:gosec // user-selected path
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{
		Path: path, Size: st.Size(), Mode: st.Mode().String(),
		ModTime: st.ModTime(), IsDir: st.IsDir(),
	}, nil
}

// ConvertHexToText decodes a hex string under an encoding (converter tools).
func (a *App) ConvertHexToText(hexStr, encName string) (string, error) {
	b, err := encoding.HexToBytes(hexStr)
	if err != nil {
		return "", err
	}
	enc, err := encoding.ParseEncoding(encName)
	if err != nil {
		return "", err
	}
	return encoding.Decode(enc, b), nil
}

// ConvertTextToHex encodes text under an encoding and returns spaced hex.
func (a *App) ConvertTextToHex(text, encName string) (string, error) {
	enc, err := encoding.ParseEncoding(encName)
	if err != nil {
		return "", err
	}
	return encoding.SpacedHex(encoding.Encode(enc, text)), nil
}

// ConvertIntelHex decodes an Intel HEX stream to raw bytes + origin.
func (a *App) ConvertIntelHex(text string) ([]byte, uint64, error) {
	img, err := encoding.DecodeIntelHex(strings.NewReader(text))
	if err != nil {
		return nil, 0, err
	}
	return img.Data, img.Origin, nil
}

// ConvertSRecords decodes a Motorola S-record stream to raw bytes + origin.
func (a *App) ConvertSRecords(text string) ([]byte, uint64, error) {
	img, err := encoding.DecodeSRecords(strings.NewReader(text))
	if err != nil {
		return nil, 0, err
	}
	return img.Data, img.Origin, nil
}
