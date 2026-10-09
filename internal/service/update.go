package service

import (
	"context"
	"os"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/update"
	"github.com/IshikawaUta/gohex/pkg/version"
)

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
