// Package update checks whether a newer GoHex release exists.
//
// The check is strictly opt-in: nothing in this package is called unless
// the examiner enables it with GOHEX_UPDATE_CHECK=1 (see docs/legal.md —
// GoHex makes no outbound connections by default). A failed check is
// reported as data in Result.Error, never as a panic or a Go error that
// could take the application down.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultURL is the GitHub "latest release" endpoint for GoHex. The
// response is GitHub's release shape: {"tag_name","html_url","body"}.
const DefaultURL = "https://api.github.com/repos/IshikawaUta/gohex/releases/latest"

// maxBody caps the API response — releases are tiny JSON documents, so
// 1 MiB is already extravagant.
const maxBody = 1 << 20

// Result reports one update check.
type Result struct {
	Current   string `json:"current"`
	Latest    string `json:"latest,omitempty"`
	URL       string `json:"url,omitempty"`
	Notes     string `json:"notes,omitempty"`
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
}

// Checker queries a "latest release" endpoint.
type Checker struct {
	URL    string // defaults to DefaultURL
	Client *http.Client
}

// New returns a Checker with the default endpoint and a client with a
// 10-second timeout.
func New() *Checker {
	return &Checker{URL: DefaultURL, Client: &http.Client{Timeout: 10 * time.Second}}
}

// Check queries the endpoint and compares the latest tag against the
// running version. Network and parse failures land in Result.Error;
// Check itself returns no error on purpose — an unavailable update
// server is information, not a fault.
func (c *Checker) Check(ctx context.Context, current string) Result {
	res := Result{Current: current}
	url := c.URL
	if url == "" {
		url = DefaultURL
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "GoHex/"+current)
	resp, err := client.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		res.Error = fmt.Sprintf("update check: HTTP %d", resp.StatusCode)
		return res
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if int64(len(body)) > maxBody {
		res.Error = "update check: response too large"
		return res
	}
	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Body    string `json:"body"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		res.Error = "update check: bad response: " + err.Error()
		return res
	}
	latest := strings.TrimPrefix(strings.TrimSpace(release.TagName), "v")
	if latest == "" {
		res.Error = "update check: empty tag_name"
		return res
	}
	res.Latest = latest
	res.URL = release.HTMLURL
	res.Notes = release.Body
	res.Available = Compare(latest, strings.TrimPrefix(current, "v")) > 0
	return res
}

// Compare orders two dotted version strings: numeric segments first,
// then prerelease precedence ("1.0.0" > "1.0.0-rc1", "rc2" > "rc1").
// Missing segments count as zero; build metadata after '+' is ignored.
// Returns -1, 0 or +1.
func Compare(a, b string) int {
	an, apre := split(a)
	bn, bpre := split(b)
	for i := 0; i < len(an) || i < len(bn); i++ {
		x, y := 0, 0
		if i < len(an) {
			x = an[i]
		}
		if i < len(bn) {
			y = bn[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case apre == bpre:
		return 0
	case apre == "": // a plain release outranks its prereleases
		return 1
	case bpre == "":
		return -1
	}
	return strings.Compare(apre, bpre)
}

// split separates the numeric segments from the prerelease suffix.
func split(v string) ([]int, string) {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i] // build metadata never affects precedence
	}
	pre := ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre, v = v[i+1:], v[:i]
	}
	parts := strings.Split(v, ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			break // "1.2.x" stops at the junk segment; the rest is 0
		}
		nums = append(nums, n)
	}
	return nums, pre
}

// maxAsset caps a release download. GoHex binaries are tens of MiB;
// anything near this cap is either the wrong file or an attack.
const maxAsset = 256 << 20 // 256 MiB

// Download fetches a release asset and verifies it against wantSHA256
// (lowercase or uppercase hex, 64 characters). The body is streamed
// through the hash and a size cap, so a lying Content-Length cannot
// allocate the process to death. The verified bytes are written to
// dstPath with O_EXCL — an existing file is never overwritten.
//
// Download makes no connection unless the caller asks for one; it is
// the second half of the opt-in update flow (Check tells you a release
// exists, Download fetches it).
func (c *Checker) Download(ctx context.Context, url, wantSHA256, dstPath string) (int64, string, error) {
	if url == "" {
		return 0, "", fmt.Errorf("update download: empty url")
	}
	if len(wantSHA256) != 64 {
		return 0, "", fmt.Errorf("update download: wantSHA256 must be 64 hex chars")
	}
	if dstPath == "" {
		return 0, "", fmt.Errorf("update download: empty destination")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "GoHex/update-download")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("update download: HTTP %d", resp.StatusCode)
	}

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return 0, "", fmt.Errorf("update download: %w", err)
	}
	abort := func(err error) (int64, string, error) {
		dst.Close()
		os.Remove(dstPath)
		return 0, "", err
	}

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(resp.Body, maxAsset+1))
	if err != nil {
		return abort(fmt.Errorf("update download: %w", err))
	}
	if n > maxAsset {
		return abort(fmt.Errorf("update download: asset exceeds %d bytes", int64(maxAsset)))
	}
	if err := dst.Close(); err != nil {
		return abort(fmt.Errorf("update download close: %w", err))
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, wantSHA256) {
		os.Remove(dstPath)
		return 0, "", fmt.Errorf("update download: sha256 mismatch: got %s want %s", got, strings.ToLower(wantSHA256))
	}
	return n, got, nil
}
