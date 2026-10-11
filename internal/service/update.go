package service

import (
	"context"
	"errors"
	"os"
	"strconv"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/update"
	"github.com/IshikawaUta/gohex/pkg/version"
)

// errUpdateDisabled mirrors the UpdateCheck contract: the feature can be
// hard-disabled, so a refused call is a policy decision, not a crash.
var errUpdateDisabled = errors.New("service: update download is disabled (GOHEX_UPDATE_CHECK=0)")

// updateAllowed reports whether user-initiated update actions may run.
// GoHex performs no automatic update probes: UpdateCheck and
// UpdateDownload are only reachable from the About dialog's explicit
// buttons, so the click itself is the consent (docs/legal.md).
// Deployments that must guarantee zero outbound traffic — sealed labs —
// set GOHEX_UPDATE_CHECK=0 to refuse even those explicit actions.
func updateAllowed() bool {
	return os.Getenv("GOHEX_UPDATE_CHECK") != "0"
}

// UpdateCheck probes the GoHex GitHub releases for a newer version.
//
// The probe runs when the examiner presses "Check for updates" in the
// About dialog — that explicit click is the consent, and no automatic
// background check exists. GOHEX_UPDATE_CHECK=0 hard-disables the probe
// for sealed labs; the refusal is local and returns immediately with
// Result.Error explaining why. A failed probe (offline, server error)
// is reported in Result.Error too, never as a Go error: an update check
// must not be able to break anything else. Every run is recorded in the
// audit log.
func (a *App) UpdateCheck() (update.Result, error) {
	current := version.Version
	if !updateAllowed() {
		return update.Result{
			Current: current,
			Error:   "update checks are disabled (GOHEX_UPDATE_CHECK=0)",
		}, nil
	}
	c := update.New()
	// GOHEX_UPDATE_URL points the probe at a mirror or an offline fixture;
	// unset it falls back to the official GitHub endpoint.
	if u := os.Getenv("GOHEX_UPDATE_URL"); u != "" {
		c.URL = u
	}
	res := c.Check(context.Background(), current)
	detail := map[string]string{"op": "update-check", "current": current}
	if res.Latest != "" {
		detail["latest"] = res.Latest
	}
	if res.Available {
		detail["available"] = "true"
	}
	if res.Error != "" {
		detail["error"] = res.Error
		_ = a.log.Log(audit.Event{
			Action: audit.ActionConfig,
			Result: audit.ResultError,
			Detail: detail,
		})
		return res, nil
	}
	_ = a.log.Log(audit.Event{
		Action: audit.ActionConfig,
		Result: audit.ResultOK,
		Detail: detail,
	})
	return res, nil
}

// UpdateDownload fetches a release asset and verifies it against the
// SHA-256 the release published. Like UpdateCheck it is user-initiated
// (the examiner pastes the URL and digest in the About dialog) and only
// hard-disabled by GOHEX_UPDATE_CHECK=0. The asset lands at dstPath only
// when the digest matches — a mismatch deletes the partial file and
// reports a Go error, because a corrupted binary is a fault, not
// information. GoHex never executes the download: installing and
// launching an update stays a manual, examiner-controlled step. Every
// attempt, success or failure, is audited.
func (a *App) UpdateDownload(url, wantSHA256, dstPath string) (UpdateDownloadResult, error) {
	if !updateAllowed() {
		return UpdateDownloadResult{}, errUpdateDisabled
	}
	c := update.New()
	n, sum, err := c.Download(context.Background(), url, wantSHA256, dstPath)
	detail := map[string]string{"op": "update-download", "url": url, "dst": dstPath}
	if err != nil {
		detail["error"] = err.Error()
		_ = a.log.Log(audit.Event{
			Action: audit.ActionExport,
			Target: dstPath,
			Result: audit.ResultError,
			Detail: detail,
		})
		return UpdateDownloadResult{}, err
	}
	detail["bytes"] = strconv.FormatInt(n, 10)
	detail["sha256"] = sum
	_ = a.log.Log(audit.Event{
		Action: audit.ActionExport,
		Target: dstPath,
		Result: audit.ResultOK,
		Hash:   "sha256:" + sum,
		Detail: detail,
	})
	return UpdateDownloadResult{Path: dstPath, Bytes: n, SHA256: sum}, nil
}

// UpdateDownloadResult describes a verified download.
type UpdateDownloadResult struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
