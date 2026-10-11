package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsAreSafe(t *testing.T) {
	p := Default()
	if p.AllowUnsafeWrite || p.UpdateCheck || p.TelemetryConsent || p.SandboxMode {
		t.Fatalf("unsafe defaults: %+v", p)
	}
	if !p.EditingAllowed() {
		t.Fatal("default profile should allow normal editing")
	}
	if p.DiskWriteAllowed() {
		t.Fatal("disk writes must be denied by default (triple gate)")
	}
	if p.Theme != ThemeDark || p.BytesPerLine != 16 || p.Language == "" {
		t.Fatalf("appearance defaults: %+v", p)
	}
	if p.Profile != ProfileAnalyst {
		t.Fatalf("profile = %q", p.Profile)
	}
	if len(p.Shortcuts) == 0 || p.Shortcuts["file.open"] != "Ctrl+O" {
		t.Fatal("shortcut defaults missing")
	}
}

func TestLoadSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.json")

	// Missing file → defaults, no error.
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Theme != ThemeDark {
		t.Fatal("missing file should yield defaults")
	}

	p.Theme = ThemeHighContrast
	p.Language = "id"
	p.BytesPerLine = 32
	p.AddRecent("/evidence/a.dd")
	p.AddRecent("/evidence/b.dd")
	p.AddRecent("/evidence/a.dd") // dedup keeps first
	if err := p.Save(path); err != nil {
		t.Fatal(err)
	}

	q, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if q.Theme != ThemeHighContrast || q.Language != "id" || q.BytesPerLine != 32 {
		t.Fatalf("round trip: %+v", q)
	}
	if len(q.RecentFiles) != 2 || q.RecentFiles[0] != "/evidence/a.dd" {
		t.Fatalf("recent = %v", q.RecentFiles)
	}

	// Corrupt file must surface an error (never silently discard policy).
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("corrupt config should error")
	}
}

func TestValidation(t *testing.T) {
	p := Default()
	p.Profile = "hacker"
	if err := p.Validate(); err == nil {
		t.Error("bad profile should fail")
	}
	p = Default()
	p.Theme = "neon"
	if err := p.Validate(); err == nil {
		t.Error("bad theme should fail")
	}
	p.Theme = "custom:matrix"
	if err := p.Validate(); err != nil {
		t.Errorf("custom theme should pass: %v", err)
	}
	p = Default()
	p.Language = "fr"
	if err := p.Validate(); err == nil {
		t.Error("unsupported language should fail")
	}
	p = Default()
	p.OffsetRadix = "oct"
	if err := p.Validate(); err == nil {
		t.Error("bad radix should fail")
	}
	p = Default()
	p.RESTAPIEnable = true
	p.RESTAPIToken = ""
	if err := p.Validate(); err == nil {
		t.Error("REST API without token should fail")
	}
	// Save must refuse invalid config.
	if err := p.Save(filepath.Join(t.TempDir(), "x.json")); err == nil {
		t.Error("Save should validate")
	}
}

func TestProfilesPolicy(t *testing.T) {
	for _, prof := range []string{ProfileAnalyst, ProfileRecovery, ProfileExaminer} {
		p := Default()
		p.Profile = prof
		if !p.EditingAllowed() {
			t.Errorf("%s should allow editing", prof)
		}
	}
	p := Default()
	p.Profile = ProfileReadOnly
	if p.EditingAllowed() {
		t.Error("readonly must disable editing")
	}
	// Disk writes: allowed only with flag AND examiner profile.
	p.AllowUnsafeWrite = true
	if p.DiskWriteAllowed() {
		t.Error("flag alone must not allow writes in analyst profile")
	}
	p.Profile = ProfileExaminer
	if !p.DiskWriteAllowed() {
		t.Error("examiner + flag should allow writes")
	}
}

func TestApplyEnv(t *testing.T) {
	t.Setenv("GOHEX_THEME", "high-contrast")
	t.Setenv("GOHEX_LANG", "id")
	t.Setenv("GOHEX_PROFILE", "readonly")
	t.Setenv("GOHEX_ALLOW_UNSAFE_WRITE", "1")
	t.Setenv("GOHEX_UPDATE_CHECK", "true")
	t.Setenv("GOHEX_AUDIT_LOG", "/tmp/x.jsonl")
	p := Default()
	p.ApplyEnv()
	if p.Theme != ThemeHighContrast || p.Language != "id" || p.Profile != ProfileReadOnly {
		t.Fatalf("env overlay: %+v", p)
	}
	if !p.AllowUnsafeWrite || !p.UpdateCheck || p.AuditLogPath != "/tmp/x.jsonl" {
		t.Fatalf("env security flags: %+v", p)
	}
}

func TestAddRecentTrims(t *testing.T) {
	p := Default()
	for i := 0; i < 50; i++ {
		p.AddRecent(strings.Repeat("x", i+1))
	}
	if len(p.RecentFiles) != p.MaxRecent {
		t.Fatalf("recent len = %d, max %d", len(p.RecentFiles), p.MaxRecent)
	}
}

func TestI18nCompleteness(t *testing.T) {
	for _, lang := range Languages() {
		if lang == "en" {
			continue
		}
		if missing := MissingKeys(lang); len(missing) > 0 {
			t.Errorf("language %q missing keys: %v", lang, missing)
		}
	}
}

func TestTranslation(t *testing.T) {
	en := T("en", "menu.file.open")
	id := T("id", "menu.file.open")
	if en != "Open…" || id != "Buka…" {
		t.Fatalf("en=%q id=%q", en, id)
	}
	// Fallbacks.
	if got := T("xx", "menu.file.open"); got != "Open…" {
		t.Errorf("unknown lang fallback = %q", got)
	}
	if got := T("en", "no.such.key"); got != "no.such.key" {
		t.Errorf("missing key = %q", got)
	}
	// Format args.
	got := T("en", "dialog.unsafeWrite.step1", "/dev/sdX")
	if !strings.Contains(got, "/dev/sdX") {
		t.Errorf("format arg lost: %q", got)
	}
}

func TestNormalizeLang(t *testing.T) {
	cases := map[string]string{
		"":            "en",
		"id_ID.UTF-8": "id",
		"ID":          "id",
		"en_US.UTF-8": "en",
		"xx":          "en",
	}
	for in, want := range cases {
		if got := NormalizeLang(in); got != want {
			t.Errorf("NormalizeLang(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadReadError(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("reading a directory as config should fail")
	}
}

func TestApplyDefaultsFills(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	raw := `{"fontSize":0,"bytesPerLine":999,"maxRecent":-1,"language":"","profile":"",` +
		`"theme":"","offsetRadix":"","textEncoding":"","fontFamily":"","auditLogPath":"",` +
		`"shortcuts":{},"window":{}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.FontSize != Default().FontSize || p.BytesPerLine != Default().BytesPerLine {
		t.Fatalf("defaults not applied: %+v", p)
	}
	if p.MaxRecent != Default().MaxRecent || p.Profile != ProfileAnalyst {
		t.Fatalf("profile/recent defaults: %+v", p)
	}
	if p.Shortcuts["file.open"] != "Ctrl+O" {
		t.Fatal("shortcuts should be merged from defaults")
	}
}

func TestSaveMkdirError(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := Default()
	if err := p.Save(filepath.Join(blocker, "sub", "config.json")); err == nil {
		t.Fatal("saving under a plain file should fail")
	}
}

func TestDetectLanguageEnv(t *testing.T) {
	t.Setenv("LC_ALL", "id_ID.UTF-8")
	if got := detectLanguage(); got != "id" {
		t.Fatalf("detectLanguage = %q", got)
	}
	t.Setenv("LC_ALL", "")
	t.Setenv("LANG", "en_US.UTF-8")
	if got := detectLanguage(); got != "en" {
		t.Fatalf("detectLanguage = %q", got)
	}
}

func TestCatalog(t *testing.T) {
	en := Catalog("en")
	if len(en) == 0 {
		t.Fatal("empty EN catalog")
	}
	for _, k := range []string{"menu.file.open", "dialog.disclaimer.body"} {
		if en[k] == "" {
			t.Fatalf("missing key %q", k)
		}
	}
	id := Catalog("id")
	if len(id) < len(en) {
		t.Fatalf("ID catalog smaller: %d < %d", len(id), len(en))
	}
	// Language-specific entries override the English fallback.
	changed := 0
	for k, v := range en {
		if id[k] != v {
			changed++
		}
	}
	if changed == 0 {
		t.Fatal("ID catalog identical to EN")
	}
	// Unknown language falls back to English.
	if Catalog("xx")["menu.file.open"] != en["menu.file.open"] {
		t.Fatal("unknown lang must fall back to EN")
	}
}

func TestShortcutsValidation(t *testing.T) {
	// The stock keymap is valid.
	p := Default()
	if err := p.Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if p.Shortcuts["file.open"] != "Ctrl+O" || p.Shortcuts["search.find"] != "Ctrl+F" {
		t.Fatalf("defaults lost bindings: %v", p.Shortcuts)
	}
	// Ctrl+Shift+F / Ctrl+Shift+I are distinct chords from Ctrl+F; the
	// shift modifier is preserved by Normalize so they do not shadow.
	if p.Shortcuts["edit.fill"] != "Ctrl+Shift+F" || p.Shortcuts["edit.insert"] != "Ctrl+Shift+I" {
		t.Fatalf("defaults lost edit.fill/edit.insert bindings: %v", p.Shortcuts)
	}

	// Overrides normalise case and modifier order.
	p = Default()
	p.Shortcuts["file.open"] = "control+o"
	if err := p.Validate(); err != nil {
		t.Fatalf("alias chord: %v", err)
	}

	// Empty value unbinds an action.
	p = Default()
	p.Shortcuts["file.open"] = ""
	if err := p.Validate(); err != nil {
		t.Fatalf("unbind: %v", err)
	}

	for name, mutate := range map[string]func(p *Preferences){
		"bad chord": func(p *Preferences) { p.Shortcuts["file.open"] = "Ctrl+Notakey" },
		"unknown action": func(p *Preferences) {
			p.Shortcuts["nope.action"] = "Ctrl+O"
		},
		"duplicate chord": func(p *Preferences) { p.Shortcuts["file.new"] = "Ctrl+O" },
	} {
		p := Default()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: err = nil", name)
		}
	}
}
