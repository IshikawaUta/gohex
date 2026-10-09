// Package config loads and stores GoHex preferences: appearance (theme,
// font, columns), keyboard shortcuts, audit-log location, language, user
// profile (read-only vs editing policy) and opt-in flags. Configuration is
// JSON on disk, overridable by environment variables (GOHEX_*) and CLI flags;
// security-relevant defaults are always the safe ones (read-only, no
// telemetry, no update checks).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/IshikawaUta/gohex/internal/keymap"
)

// Theme selects the colour scheme.
type Theme string

// Available themes (a custom theme is a JSON file in the themes directory).
const (
	ThemeLight        Theme = "light"
	ThemeDark         Theme = "dark"
	ThemeHighContrast Theme = "high-contrast"
)

// Profiles — policy presets applied to the whole session.
const (
	ProfileAnalyst  = "analyst"  // full editing of opened files
	ProfileRecovery = "recovery" // editing + recovery tools front and centre
	ProfileReadOnly = "readonly" // editing disabled; pure examination
	ProfileExaminer = "examiner" // editing + audit emphasis for casework
)

// Preferences is the persisted configuration document.
type Preferences struct {
	// Appearance
	Theme        Theme  `json:"theme"`
	FontFamily   string `json:"fontFamily"`
	FontSize     int    `json:"fontSize"`
	BytesPerLine int    `json:"bytesPerLine"`
	TextEncoding string `json:"textEncoding"`
	OffsetRadix  string `json:"offsetRadix"` // "hex" | "dec"

	// Locale & accessibility
	Language     string `json:"language"` // "en" | "id"
	HighDPI      bool   `json:"highDpi"`
	ReduceMotion bool   `json:"reduceMotion"`

	// Policy & security (safe defaults)
	Profile          string `json:"profile"`
	AllowUnsafeWrite bool   `json:"allowUnsafeWrite"` // default false; CLI flag ALSO required
	AuditLogPath     string `json:"auditLogPath"`
	AuditLogEncrypt  bool   `json:"auditLogEncrypt"`  // passphrase stored out-of-band, never here
	UpdateCheck      bool   `json:"updateCheck"`      // opt-in, default false
	TelemetryConsent bool   `json:"telemetryConsent"` // opt-in, default false; no backend yet
	SandboxMode      bool   `json:"sandboxMode"`      // simulate writes without touching disk

	// Workflow
	Shortcuts     map[string]string `json:"shortcuts"`
	RecentFiles   []string          `json:"recentFiles"`
	MaxRecent     int               `json:"maxRecent"`
	ProfileWindow WindowState       `json:"window"`

	// Scripting & automation
	RESTAPIEnable bool   `json:"restApiEnable"` // binds 127.0.0.1 only, default false
	RESTAPIToken  string `json:"restApiToken,omitempty"`
	ScriptDir     string `json:"scriptDir"`
}

// WindowState remembers window geometry between sessions.
type WindowState struct {
	Width     int  `json:"width"`
	Height    int  `json:"height"`
	Maximized bool `json:"maximized"`
}

// Default returns the safe, first-run configuration.
func Default() Preferences {
	return Preferences{
		Theme:         ThemeDark,
		FontFamily:    "JetBrains Mono, Consolas, DejaVu Sans Mono, monospace",
		FontSize:      14,
		BytesPerLine:  16,
		TextEncoding:  "ASCII",
		OffsetRadix:   "hex",
		Language:      detectLanguage(),
		HighDPI:       true,
		Profile:       ProfileAnalyst,
		MaxRecent:     12,
		AuditLogPath:  DefaultAuditPath(),
		SandboxMode:   false,
		Shortcuts:     DefaultShortcuts(),
		ProfileWindow: WindowState{Width: 1280, Height: 800},
	}
}

// DefaultShortcuts returns the stock WinHex-flavoured keymap, sourced
// from the keymap engine so the action catalogue cannot drift.
func DefaultShortcuts() map[string]string {
	m := make(map[string]string)
	for _, id := range keymap.Actions() {
		if d := keymap.Default(id); d != "" {
			m[id] = d
		}
	}
	return m
}

// DefaultAuditPath returns the per-user audit log location.
func DefaultAuditPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "gohex-audit.jsonl"
	}
	return filepath.Join(dir, "gohex", "audit.jsonl")
}

// DefaultPath returns the per-user config file location.
func DefaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "gohex.json"
	}
	return filepath.Join(dir, "gohex", "config.json")
}

func detectLanguage() string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		v := os.Getenv(k)
		if v == "" {
			continue
		}
		l := strings.ToLower(v)
		if strings.HasPrefix(l, "id") {
			return "id"
		}
		return "en"
	}
	if runtime.GOOS == "windows" {
		if strings.HasPrefix(os.Getenv("LANG"), "id") {
			return "id"
		}
	}
	return "en"
}

// Load reads the config file. A missing file yields Default() without error;
// a corrupt file is an error (callers may fall back to defaults with a
// warning rather than silently discarding security settings).
func Load(path string) (Preferences, error) {
	p := Default()
	b, err := os.ReadFile(path) //nolint:gosec // user-configured path
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil
		}
		return p, fmt.Errorf("config: read %q: %w", path, err)
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, fmt.Errorf("config: parse %q: %w", path, err)
	}
	p.applyDefaults()
	if err := p.Validate(); err != nil {
		return p, err
	}
	return p, nil
}

func (p *Preferences) applyDefaults() {
	d := Default()
	if p.Theme == "" {
		p.Theme = d.Theme
	}
	if p.FontSize <= 0 || p.FontSize > 72 {
		p.FontSize = d.FontSize
	}
	if p.BytesPerLine < 4 || p.BytesPerLine > 64 {
		p.BytesPerLine = d.BytesPerLine
	}
	if p.Language == "" {
		p.Language = d.Language
	}
	if p.Profile == "" {
		p.Profile = d.Profile
	}
	if p.MaxRecent <= 0 {
		p.MaxRecent = d.MaxRecent
	}
	if p.OffsetRadix == "" {
		p.OffsetRadix = "hex"
	}
	if p.TextEncoding == "" {
		p.TextEncoding = "ASCII"
	}
	if p.FontFamily == "" {
		p.FontFamily = d.FontFamily
	}
	if p.AuditLogPath == "" {
		p.AuditLogPath = d.AuditLogPath
	}
	if p.Shortcuts == nil {
		p.Shortcuts = d.Shortcuts
	} else {
		for k, v := range d.Shortcuts {
			if _, ok := p.Shortcuts[k]; !ok {
				p.Shortcuts[k] = v
			}
		}
	}
	if p.ProfileWindow.Width <= 0 {
		p.ProfileWindow = d.ProfileWindow
	}
}

// Validate rejects configuration that cannot be honored safely.
func (p Preferences) Validate() error {
	switch p.Theme {
	case ThemeLight, ThemeDark, ThemeHighContrast:
	default:
		if !strings.HasPrefix(string(p.Theme), "custom:") {
			return fmt.Errorf("config: unknown theme %q", p.Theme)
		}
	}
	switch p.Profile {
	case ProfileAnalyst, ProfileRecovery, ProfileReadOnly, ProfileExaminer:
	default:
		return fmt.Errorf("config: unknown profile %q", p.Profile)
	}
	if p.Language != "en" && p.Language != "id" {
		return fmt.Errorf("config: unsupported language %q", p.Language)
	}
	if p.OffsetRadix != "hex" && p.OffsetRadix != "dec" {
		return fmt.Errorf("config: offset radix must be hex or dec")
	}
	if p.RESTAPIEnable && strings.TrimSpace(p.RESTAPIToken) == "" {
		return fmt.Errorf("config: REST API requires a token")
	}
	if err := keymap.Validate(p.Shortcuts); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// Save writes the config atomically (temp file + rename) with mode 0600.
func (p Preferences) Save(path string) error {
	if err := p.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("config: encode: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("config: mkdir %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "config-*.json")
	if err != nil {
		return fmt.Errorf("config: temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("config: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("config: chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("config: rename: %w", err)
	}
	return nil
}

// EditingAllowed reports whether the active profile permits document edits.
// The read-only profile is a hard policy, not a default.
func (p Preferences) EditingAllowed() bool { return p.Profile != ProfileReadOnly }

// DiskWriteAllowed reports whether physical-disk writes are permitted by
// configuration. The CLI flag and the two-step dialog are still required —
// this is only the first of three gates.
func (p Preferences) DiskWriteAllowed() bool {
	return p.AllowUnsafeWrite && p.Profile == ProfileExaminer
}

// AddRecent prepends path to the recent-files list, deduplicating and
// trimming to MaxRecent.
func (p *Preferences) AddRecent(path string) {
	out := []string{path}
	for _, r := range p.RecentFiles {
		if r == path || len(out) >= p.MaxRecent {
			continue
		}
		out = append(out, r)
	}
	p.RecentFiles = out
}

// ApplyEnv overlays GOHEX_* environment variables (documented in
// docs/user-guide.md): GOHEX_THEME, GOHEX_LANG, GOHEX_PROFILE,
// GOHEX_ALLOW_UNSAFE_WRITE=1, GOHEX_UPDATE_CHECK=1.
func (p *Preferences) ApplyEnv() {
	if v := os.Getenv("GOHEX_THEME"); v != "" {
		p.Theme = Theme(v)
	}
	if v := os.Getenv("GOHEX_LANG"); v != "" {
		p.Language = v
	}
	if v := os.Getenv("GOHEX_PROFILE"); v != "" {
		p.Profile = v
	}
	if v := os.Getenv("GOHEX_ALLOW_UNSAFE_WRITE"); v == "1" || strings.EqualFold(v, "true") {
		p.AllowUnsafeWrite = true
	}
	if v := os.Getenv("GOHEX_UPDATE_CHECK"); v == "1" || strings.EqualFold(v, "true") {
		p.UpdateCheck = true
	}
	if v := os.Getenv("GOHEX_AUDIT_LOG"); v != "" {
		p.AuditLogPath = v
	}
}
