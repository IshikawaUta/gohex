package keymap

import (
	"testing"
)

func TestParseCanonical(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"Ctrl+O", "Ctrl+O"},
		{"ctrl+o", "Ctrl+O"},
		{"CONTROL+O", "Ctrl+O"},
		{"Ctrl+Shift+S", "Ctrl+Shift+S"},
		{"Shift+Ctrl+S", "Ctrl+Shift+S"}, // modifier order is fixed
		{"cmd+k", "Meta+K"},
		{"Command+K", "Meta+K"},
		{"Super+K", "Meta+K"},
		{"Win+K", "Meta+K"},
		{"Alt+Option+F2", "Alt+F2"},
		{"f3", "F3"},
		{"F3", "F3"},
		{"shift+f3", "Shift+F3"},
		{"f12", "F12"},
		{"f24", "F24"},
		{"Ctrl+,", "Ctrl+,"},
		{"ctrl+space", "Ctrl+Space"},
		{"Ctrl+Return", "Ctrl+Enter"},
		{"Esc", "Escape"},
		{"Ctrl+PgUp", "Ctrl+PageUp"},
		{"ctrl+pgdn", "Ctrl+PageDown"},
		{"Ctrl++", "Ctrl++"},
		{"Ctrl+Meta+A", "Ctrl+Meta+A"},
	} {
		c, err := Parse(tc.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tc.in, err)
			continue
		}
		if got := c.String(); got != tc.want {
			t.Errorf("Parse(%q).String() = %q, want %q", tc.in, got, tc.want)
		}
		norm, err := Normalize(tc.in)
		if err != nil || norm != tc.want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", tc.in, norm, err, tc.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"", "  ", "Foo+O", "Ctrl+O+", "Ctrl+Notakey", "F25", "F0", "ab"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q): err = nil, want error", in)
		}
	}
	// Trailing "+" after a modifier is the plus key, not an error.
	if c, err := Parse("Ctrl+"); err != nil || c.String() != "Ctrl++" {
		t.Errorf(`Parse("Ctrl+") = %v, %v`, c, err)
	}
	if c, err := Parse("Ctrl+Shift+"); err != nil || c.String() != "Ctrl+Shift++" {
		t.Errorf(`Parse("Ctrl+Shift+") = %v, %v`, c, err)
	}
}

func TestActionsAndDefaults(t *testing.T) {
	actions := Actions()
	if len(actions) < 10 {
		t.Fatalf("Actions() = %d entries", len(actions))
	}
	for _, id := range actions {
		if d := Default(id); d == "" {
			t.Errorf("action %q has no default chord", id)
		}
	}
	if Default("nope") != "" {
		t.Error("Default of unknown action should be empty")
	}
	// Every default chord must itself be canonical and unique.
	seen := map[string]string{}
	for _, id := range actions {
		d := Default(id)
		norm, err := Normalize(d)
		if err != nil {
			t.Errorf("default %q for %q does not parse: %v", d, id, err)
			continue
		}
		if norm != d {
			t.Errorf("default for %q is not canonical: %q → %q", id, d, norm)
		}
		if other, clash := seen[norm]; clash {
			t.Errorf("defaults %q and %q both use %s", other, id, norm)
		}
		seen[norm] = id
	}
}

func TestValidate(t *testing.T) {
	good := map[string]string{}
	for _, id := range Actions() {
		good[id] = Default(id)
	}
	if err := Validate(good); err != nil {
		t.Fatalf("defaults: %v", err)
	}

	withUnbind := map[string]string{"file.open": ""}
	if err := Validate(withUnbind); err != nil {
		t.Errorf("unbind: %v", err)
	}

	for name, m := range map[string]map[string]string{
		"unknown action": {"nope.open": "Ctrl+O"},
		"bad chord":      {"file.open": "Ctrl+Notakey"},
		"clash":          {"file.open": "Ctrl+O", "file.new": "ctrl+o"},
		"clash unbound":  {"file.open": "Ctrl+O", "file.new": "Ctrl+O"},
	} {
		if err := Validate(m); err == nil {
			t.Errorf("%s: err = nil", name)
		}
	}
}

func TestResolve(t *testing.T) {
	m := map[string]string{"file.open": "Ctrl+O", "search.next": "F3", "off": ""}
	if action, ok := Resolve(m, "ctrl+o"); !ok || action != "file.open" {
		t.Errorf("Resolve ctrl+o = %q %v", action, ok)
	}
	if action, ok := Resolve(m, "F3"); !ok || action != "search.next" {
		t.Errorf("Resolve F3 = %q %v", action, ok)
	}
	if _, ok := Resolve(m, "Ctrl+P"); ok {
		t.Error("Resolve unbound chord should miss")
	}
	if _, ok := Resolve(m, "!!!"); ok {
		t.Error("Resolve garbage should miss")
	}
	if action, ok := Resolve(m, "ctrl+O"); !ok || action != "file.open" {
		t.Errorf("Resolve case-insensitive = %q %v", action, ok)
	}
}
