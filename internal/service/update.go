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

// errUpdateDisabled mirrors the UpdateCheck contract: the feature is
// opt-in, so a disabled call is a refusal, not a crash.
var errUpdateDisabled = errors.New("service: update download is disabled (set GOHEX_UPDATE_CHECK=1 to enable)")

// UpdateCheck probes the GoHex GitHub releases for a newer version.
//
// GoHex makes no outbound connections by default (docs/legal.md): the
// probe only runs when the examiner opts in with GOHEX_UPDATE_CHECK=1.
// When disabled — the default — the call is local and returns immediately
// with Result.Error explaining why. A failed probe (offline, server error)
// is reported in Result.Error too, never as a Go error: an update check
// must not be able to break anything else. Enabled runs are recorded in
// the audit log.
func (a *App) UpdateCheck() (update.Result, error) {
	current := version.Version
	if os.Getenv("GOHEX_UPDATE_CHECK") != "1" {
		return update.Result{
			Current: current,
			Error:   "update checks are disabled (set GOHEX_UPDATE_CHECK=1 to enable)",
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
// SHA-256 the release published. The same opt-in gate as UpdateCheck
// applies (GOHEX_UPDATE_CHECK=1); nothing is downloaded otherwise. The
// asset lands at dstPath only when the digest matches — a mismatch
// deletes the partial file and reports a Go error, because a corrupted
// binary is a fault, not information. GoHex never executes the download:
// installing and launching an update stays a manual, examiner-controlled
// step. Every attempt, success or failure, is audited.
func (a *App) UpdateDownload(url, wantSHA256, dstPath string) (UpdateDownloadResult, error) {
	if os.Getenv("GOHEX_UPDATE_CHECK") != "1" {
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
