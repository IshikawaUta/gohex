package service

import (
	"bytes"
	"crypto/sha256"
	stdhex "encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/forensics"
)

// Report formats CaseReport accepts.
const (
	caseFormatHTML = "html"
	caseFormatJSON = "json"
)

// errNoCase is returned by every case operation when nothing is open. It is
// a programming error on the UI side rather than a data problem, so it never
// needs a stack of context.
var errNoCase = errors.New("service: no case is open")

// CaseState is the whole case view the front end needs: whether one is open,
// which file it last lived at, and the case itself.
type CaseState struct {
	Open bool            `json:"open"`
	Path string          `json:"path,omitempty"`
	Case *forensics.Case `json:"case,omitempty"`
}

// CaseState reports the case currently held by the service, if any. It reads
// a pointer under the lock and copies nothing: the case is only ever replaced
// wholesale, never mutated behind the caller's back.
func (a *App) CaseState() CaseState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.caseStateLocked()
}

func (a *App) caseStateLocked() CaseState {
	if a.curCase == nil {
		return CaseState{}
	}
	return CaseState{Open: true, Path: a.casePath, Case: a.curCase}
}

// CaseNew starts a new, empty case in memory. An already-open case is a
// refusal, not a silent replacement: the examiner may have unsaved findings.
func (a *App) CaseNew(name, examiner, description string) (CaseState, error) {
	c, err := forensics.New(name, examiner, description)
	if err != nil {
		return CaseState{}, fmt.Errorf("service: case new: %w", err)
	}
	a.mu.Lock()
	if a.curCase != nil {
		id := a.curCase.ID
		a.mu.Unlock()
		return CaseState{}, fmt.Errorf("service: case new: case %s is still open — save and close it first", id)
	}
	a.curCase = c
	a.casePath = ""
	state := a.caseStateLocked()
	a.mu.Unlock()

	_ = a.log.Log(audit.Event{
		Action: audit.ActionCase,
		Target: c.ID,
		Result: audit.ResultOK,
		Detail: map[string]string{"op": "new", "name": c.Name, "examiner": c.Examiner},
	})
	return state, nil
}

// CaseOpen loads a case file. The file must already be a valid case: a
// half-written or foreign JSON document is refused rather than imported.
func (a *App) CaseOpen(path string) (CaseState, error) {
	if strings.TrimSpace(path) == "" {
		return CaseState{}, errors.New("service: case open: empty path")
	}
	abs := absPath(path)
	c, err := forensics.Open(abs)
	if err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionCase,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "open", "error": err.Error()},
		})
		return CaseState{}, fmt.Errorf("service: case open: %w", err)
	}
	a.mu.Lock()
	if a.curCase != nil {
		id := a.curCase.ID
		a.mu.Unlock()
		return CaseState{}, fmt.Errorf("service: case open: case %s is still open — save and close it first", id)
	}
	a.curCase = c
	a.casePath = abs
	state := a.caseStateLocked()
	a.mu.Unlock()

	_ = a.log.Log(audit.Event{
		Action: audit.ActionCase,
		Target: abs,
		Result: audit.ResultOK,
		Detail: map[string]string{
			"op":       "open",
			"case":     c.ID,
			"name":     c.Name,
			"evidence": strconv.Itoa(len(c.Evidence)),
			"findings": strconv.Itoa(len(c.Findings)),
			"events":   strconv.Itoa(len(c.Events)),
		},
	})
	return state, nil
}

// CaseClose releases the open case without saving it. Discarding unsaved work
// is recorded so a later "where did that finding go" has an answer.
func (a *App) CaseClose() error {
	a.mu.Lock()
	c, path := a.curCase, a.casePath
	a.curCase = nil
	a.casePath = ""
	a.mu.Unlock()
	if c == nil {
		return nil
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionCase,
		Target: path,
		Result: audit.ResultOK,
		Detail: map[string]string{"op": "close", "case": c.ID, "name": c.Name},
	})
	return nil
}

// CaseSetMeta updates the descriptive fields of the open case.
func (a *App) CaseSetMeta(name, examiner, description string) (CaseState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.curCase == nil {
		return CaseState{}, errNoCase
	}
	if err := a.curCase.SetMeta(name, examiner, description); err != nil {
		return CaseState{}, fmt.Errorf("service: case meta: %w", err)
	}
	return a.caseStateLocked(), nil
}

// CaseSave writes the open case to path. The case file is the record of the
// investigation, so it is hashed and the hash goes into the audit log.
func (a *App) CaseSave(path string) (SaveResult, error) {
	if strings.TrimSpace(path) == "" {
		return SaveResult{}, errors.New("service: case save: empty path")
	}
	a.mu.Lock()
	c := a.curCase
	a.mu.Unlock()
	if c == nil {
		return SaveResult{}, errNoCase
	}
	abs := absPath(path)
	if err := c.Save(abs); err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionCase,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "save", "case": c.ID, "error": err.Error()},
		})
		return SaveResult{}, fmt.Errorf("service: case save: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return SaveResult{}, err
	}
	sum, err := a.hashFileSHA256(abs)
	if err != nil {
		return SaveResult{}, err
	}
	a.mu.Lock()
	if a.curCase == c {
		a.casePath = abs
	}
	a.mu.Unlock()

	_ = a.log.Log(audit.Event{
		Action: audit.ActionCase,
		Target: abs,
		Result: audit.ResultOK,
		Hash:   "sha256:" + sum,
		Detail: map[string]string{
			"op":       "save",
			"case":     c.ID,
			"name":     c.Name,
			"evidence": strconv.Itoa(len(c.Evidence)),
			"bytes":    strconv.FormatInt(st.Size(), 10),
		},
	})
	return SaveResult{Path: abs, BytesSaved: st.Size(), Mode: "case", SHA256: sum}, nil
}

// CaseEvidenceAdd hashes the file at path and records it in the open case.
// Hashing happens outside the lock — a multi-gigabyte image must not freeze
// the rest of the application — and the entry is only added if the same case
// is still open when the digest is ready.
func (a *App) CaseEvidenceAdd(path, kind, note string) (CaseState, error) {
	a.mu.Lock()
	c := a.curCase
	a.mu.Unlock()
	if c == nil {
		return CaseState{}, errNoCase
	}

	ev, err := forensics.EvidenceFromPath(absPath(path), kind, note)
	if err != nil {
		_ = a.log.Log(audit.Event{
			Action: audit.ActionImport,
			Target: path,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "import", "case": c.ID, "error": err.Error()},
		})
		return CaseState{}, fmt.Errorf("service: case evidence: %w", err)
	}

	a.mu.Lock()
	if a.curCase != c {
		a.mu.Unlock()
		return CaseState{}, errors.New("service: case evidence: the case was closed while hashing")
	}
	if err := c.AddEvidence(ev); err != nil {
		a.mu.Unlock()
		return CaseState{}, fmt.Errorf("service: case evidence: %w", err)
	}
	// AddEvidence assigns the identifier to its own copy, so read it back
	// from the entry that is now in the case.
	added := c.Evidence[len(c.Evidence)-1]
	state := a.caseStateLocked()
	id := added.ID
	a.mu.Unlock()

	_ = a.log.Log(audit.Event{
		Action: audit.ActionImport,
		Target: ev.Path,
		Result: audit.ResultOK,
		Hash:   "sha256:" + ev.SHA256,
		Detail: map[string]string{
			"op":       "import",
			"case":     c.ID,
			"evidence": id,
			"kind":     ev.Kind,
			"size":     strconv.FormatInt(ev.Size, 10),
		},
	})
	return state, nil
}

// CaseEvidenceVerify re-hashes one evidence file and reports whether it still
// matches the digest recorded when it was added. Both outcomes are audited:
// a mismatch is the finding, not a failure to record.
func (a *App) CaseEvidenceVerify(id string) (forensics.VerifyResult, error) {
	a.mu.Lock()
	c := a.curCase
	a.mu.Unlock()
	if c == nil {
		return forensics.VerifyResult{}, errNoCase
	}
	res, err := c.VerifyEvidence(strings.TrimSpace(id))
	if err != nil {
		return forensics.VerifyResult{}, fmt.Errorf("service: case verify: %w", err)
	}
	// A mismatch is recorded as an error: an auditor scanning the log for
	// failed integrity checks must find it without knowing the vocabulary.
	result := audit.ResultOK
	match := "true"
	if !res.Match {
		result = audit.ResultError
		match = "false"
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionHashVerify,
		Target: res.Path,
		Result: result,
		Hash:   "sha256:" + res.Actual,
		Detail: map[string]string{
			"case":     c.ID,
			"evidence": res.EvidenceID,
			"expected": res.Expected,
			"match":    match,
		},
	})
	return res, nil
}

// FindingInput is what a caller supplies for a finding. The identifier and
// the timestamp belong to the case, not to whoever types the finding in, so
// they are deliberately absent from this shape.
type FindingInput struct {
	Title      string `json:"title"`
	Detail     string `json:"detail,omitempty"`
	Severity   string `json:"severity,omitempty"`
	EvidenceID string `json:"evidenceId,omitempty"`
}

// CaseFindingAdd records a conclusion in the open case.
func (a *App) CaseFindingAdd(in FindingInput) (CaseState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.curCase == nil {
		return CaseState{}, errNoCase
	}
	f := forensics.Finding{
		Title:      in.Title,
		Detail:     in.Detail,
		Severity:   in.Severity,
		EvidenceID: in.EvidenceID,
	}
	if err := a.curCase.AddFinding(f); err != nil {
		return CaseState{}, fmt.Errorf("service: case finding: %w", err)
	}
	return a.caseStateLocked(), nil
}

// CaseEventAdd appends one point to the case timeline.
func (a *App) CaseEventAdd(e forensics.Event) (CaseState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.curCase == nil {
		return CaseState{}, errNoCase
	}
	if err := a.curCase.AddEvent(e); err != nil {
		return CaseState{}, fmt.Errorf("service: case event: %w", err)
	}
	return a.caseStateLocked(), nil
}

// CaseReport renders the open case to dstPath, which must not exist. The
// destination is hashed, so a report handed to someone else can be tied back
// to this run, and the render is audited as an export.
func (a *App) CaseReport(format, dstPath string) (SaveResult, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format != caseFormatHTML && format != caseFormatJSON {
		return SaveResult{}, fmt.Errorf("service: case report: unknown format %q", format)
	}
	if strings.TrimSpace(dstPath) == "" {
		return SaveResult{}, errors.New("service: case report: empty destination")
	}
	a.mu.Lock()
	c := a.curCase
	a.mu.Unlock()
	if c == nil {
		return SaveResult{}, errNoCase
	}

	var buf bytes.Buffer
	generated := time.Now().UTC()
	var err error
	switch format {
	case caseFormatJSON:
		err = forensics.WriteJSON(&buf, c, generated)
	default:
		err = forensics.WriteHTML(&buf, c, generated)
	}
	if err != nil {
		return SaveResult{}, err
	}
	payload := buf.Bytes()

	abs := absPath(dstPath)
	dst, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return SaveResult{}, fmt.Errorf("service: case report: %w", err)
	}
	abort := func(err error) (SaveResult, error) {
		dst.Close()
		os.Remove(abs)
		_ = a.log.Log(audit.Event{
			Action: audit.ActionExport,
			Target: abs,
			Result: audit.ResultError,
			Detail: map[string]string{"op": "report", "case": c.ID, "error": err.Error()},
		})
		return SaveResult{}, err
	}
	h := sha256.New()
	h.Write(payload)
	n, err := dst.Write(payload)
	if err != nil {
		return abort(fmt.Errorf("service: case report: %w", err))
	}
	if err := dst.Close(); err != nil {
		return abort(fmt.Errorf("service: case report close: %w", err))
	}
	sum := stdhex.EncodeToString(h.Sum(nil))

	_ = a.log.Log(audit.Event{
		Action: audit.ActionExport,
		Target: abs,
		Result: audit.ResultOK,
		Hash:   "sha256:" + sum,
		Detail: map[string]string{
			"op":       "report",
			"case":     c.ID,
			"format":   format,
			"bytes":    strconv.Itoa(n),
			"evidence": strconv.Itoa(len(c.Evidence)),
			"findings": strconv.Itoa(len(c.Findings)),
			"events":   strconv.Itoa(len(c.Events)),
		},
	})
	return SaveResult{Path: abs, BytesSaved: int64(n), Mode: "report", SHA256: sum}, nil
}
