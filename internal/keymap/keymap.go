// Package keymap is the configurable keymap engine: it canonicalises
// shortcut chords, validates user keymaps, and resolves chords to action
// IDs. The GUI captures keyboard events and renders chords in the same
// canonical form; this package is the single source of truth for what a
// valid binding looks like.
//
// Chords are "Modifier+...+key" strings: modifiers in the fixed order
// Ctrl, Alt, Shift, Meta (aliases Control, Cmd, Command, Super, Win,
// Option are folded in), then one base key — a lowercase letter or
// digit, an F-key (f1..f24), or a named key (space, tab, enter, escape,
// backspace, delete, home, end, pageup, pagedown, up, down, left,
// right, and single punctuation such as ",").
package keymap

import (
	"fmt"
	"sort"
	"strings"
)

// Actions returns every known action ID, sorted. A keymap entry whose
// action is not in this list is rejected by Validate.
func Actions() []string {
	out := make([]string, 0, len(defaultActions))
	for id := range defaultActions {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Default returns the stock chord for an action ("" if the action has no
// default binding).
func Default(action string) string { return defaultActions[action] }

// defaultActions is the stock WinHex-flavoured keymap. It is also the
// catalogue of valid action IDs — config.DefaultShortcuts and the GUI
// dispatcher must stay in sync with it.
var defaultActions = map[string]string{
	"file.open":        "Ctrl+O",
	"file.new":         "Ctrl+N",
	"file.save":        "Ctrl+S",
	"file.saveAs":      "Ctrl+Shift+S",
	"edit.undo":        "Ctrl+Z",
	"edit.redo":        "Ctrl+Y",
	"edit.cut":         "Ctrl+X",
	"edit.copy":        "Ctrl+C",
	"edit.copyText":    "Ctrl+Shift+C",
	"edit.paste":       "Ctrl+V",
	"edit.selectAll":   "Ctrl+A",
	"search.find":      "Ctrl+F",
	"search.replace":   "Ctrl+H",
	"search.next":      "F3",
	"search.prev":      "Shift+F3",
	"goto.offset":      "Ctrl+G",
	"goto.back":        "Alt+Left",
	"goto.forward":     "Alt+Right",
	"edit.bookmark":    "Ctrl+D",
	"view.bookmarks":   "Ctrl+Shift+B",
	"view.theme":       "Ctrl+Shift+T",
	"preferences.open": "Ctrl+,",
	"help.shortcuts":   "F1",
}

// Modifiers are the chord's modifier keys.
type Modifiers struct {
	Ctrl  bool
	Alt   bool
	Shift bool
	Meta  bool // Cmd on macOS, Win/Super elsewhere
}

// Chord is one parsed binding.
type Chord struct {
	Mods Modifiers
	Key  string // canonical base key: "o", "f3", ",", "space"
}

var modAliases = map[string]string{
	"ctrl":    "ctrl",
	"control": "ctrl",
	"alt":     "alt",
	"opt":     "alt",
	"option":  "alt",
	"shift":   "shift",
	"meta":    "meta",
	"cmd":     "meta",
	"command": "meta",
	"super":   "meta",
	"win":     "meta",
}

var keyAliases = map[string]string{
	"return":   "enter",
	"esc":      "escape",
	"pgup":     "pageup",
	"pgdn":     "pagedown",
	"del":      "delete",
	"ins":      "insert",
	"spacebar": "space",
}

var namedKeys = map[string]bool{
	"space": true, "tab": true, "enter": true, "escape": true,
	"backspace": true, "delete": true, "insert": true,
	"home": true, "end": true, "pageup": true, "pagedown": true,
	"up": true, "down": true, "left": true, "right": true,
}

// Parse reads a chord string ("Ctrl+Shift+S") in any casing or alias
// form and returns its canonical Chord.
func Parse(s string) (Chord, error) {
	parts := strings.Split(s, "+")
	// A trailing "+" is the literal plus key: "Ctrl++" splits into
	// ["Ctrl", "", ""], so fold double-empty tails into one "+".
	for len(parts) >= 3 && parts[len(parts)-1] == "" && parts[len(parts)-2] == "" {
		parts = parts[:len(parts)-1]
		parts[len(parts)-1] = "+"
	}
	// A single trailing empty after a modifier ("Ctrl+") is the plus key;
	// after a base key ("Ctrl+O+") it is a plain empty-base error.
	if len(parts) >= 2 && parts[len(parts)-1] == "" {
		prev := strings.ToLower(parts[len(parts)-2])
		if _, ok := modAliases[prev]; ok {
			parts[len(parts)-1] = "+"
		}
	}
	if len(parts) == 0 || parts[0] == "" {
		return Chord{}, fmt.Errorf("keymap: empty chord")
	}
	var c Chord
	for i, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			return Chord{}, fmt.Errorf("keymap: empty segment in %q", s)
		}
		last := i == len(parts)-1
		if !last {
			m, ok := modAliases[p]
			if !ok {
				return Chord{}, fmt.Errorf("keymap: %q is not a modifier", p)
			}
			switch m {
			case "ctrl":
				c.Mods.Ctrl = true
			case "alt":
				c.Mods.Alt = true
			case "shift":
				c.Mods.Shift = true
			case "meta":
				c.Mods.Meta = true
			}
			continue
		}
		key, err := canonicalKey(p)
		if err != nil {
			return Chord{}, err
		}
		c.Key = key
	}
	return c, nil
}

// canonicalKey folds one base key onto its canonical name.
func canonicalKey(p string) (string, error) {
	if alias, ok := keyAliases[p]; ok {
		p = alias
	}
	if len(p) == 1 {
		switch p {
		case "+", "-", "=", "[", "]", ";", "'", ",", ".", "/", "\\", "`":
			return p, nil
		}
		if p >= "a" && p <= "z" || p >= "0" && p <= "9" {
			return p, nil
		}
		return "", fmt.Errorf("keymap: unsupported key %q", p)
	}
	if len(p) == 2 && p[0] == 'f' {
		if n := p[1] - '0'; n >= 1 && n <= 9 {
			return p, nil
		}
	}
	if len(p) == 3 && p[0] == 'f' {
		if p[1] == '1' || p[1] == '2' {
			n := (p[1]-'0')*10 + (p[2] - '0')
			if (p[1] == '1' && n >= 10 && n <= 19) || (p[1] == '2' && n >= 20 && n <= 24) {
				return p, nil
			}
		}
	}
	if namedKeys[p] {
		return p, nil
	}
	return "", fmt.Errorf("keymap: unsupported key %q", p)
}

// namedDisplay is the display spelling of the named keys.
var namedDisplay = map[string]string{
	"space": "Space", "tab": "Tab", "enter": "Enter", "escape": "Escape",
	"backspace": "Backspace", "delete": "Delete", "insert": "Insert",
	"home": "Home", "end": "End", "pageup": "PageUp", "pagedown": "PageDown",
	"up": "Up", "down": "Down", "left": "Left", "right": "Right",
}

// String renders the chord in canonical form: modifiers in fixed order,
// letters and F-keys uppercased, named keys title-cased ("Ctrl+O",
// "Shift+F3", "Ctrl+PageUp").
func (c Chord) String() string {
	var b strings.Builder
	if c.Mods.Ctrl {
		b.WriteString("Ctrl+")
	}
	if c.Mods.Alt {
		b.WriteString("Alt+")
	}
	if c.Mods.Shift {
		b.WriteString("Shift+")
	}
	if c.Mods.Meta {
		b.WriteString("Meta+")
	}
	key := c.Key
	switch {
	case len(key) == 1 && key >= "a" && key <= "z":
		key = strings.ToUpper(key)
	case len(key) >= 2 && key[0] == 'f' && key[1] >= '0' && key[1] <= '9':
		key = "F" + key[1:]
	default:
		if disp, ok := namedDisplay[key]; ok {
			key = disp
		}
	}
	b.WriteString(key)
	return b.String()
}

// Normalize parses s and returns its canonical string form.
func Normalize(s string) (string, error) {
	c, err := Parse(s)
	if err != nil {
		return "", err
	}
	return c.String(), nil
}

// Validate checks a full keymap: every action ID must be known, every
// chord must parse (an empty value unbinds the action), and no two
// actions may claim the same chord. The first problem found is returned.
func Validate(m map[string]string) error {
	byChord := map[string]string{}
	for _, action := range sortedKeys(m) {
		chord := m[action]
		if _, ok := defaultActions[action]; !ok {
			return fmt.Errorf("keymap: unknown action %q", action)
		}
		if chord == "" { // explicit unbind
			continue
		}
		norm, err := Normalize(chord)
		if err != nil {
			return fmt.Errorf("keymap: action %q: %w", action, err)
		}
		if other, clash := byChord[norm]; clash {
			return fmt.Errorf("keymap: %q and %q both bound to %s", other, action, norm)
		}
		byChord[norm] = action
	}
	return nil
}

// Resolve maps a chord (in any accepted spelling) to its action ID.
func Resolve(m map[string]string, chord string) (string, bool) {
	norm, err := Normalize(chord)
	if err != nil {
		return "", false
	}
	for action, c := range m {
		if c == "" {
			continue
		}
		if n, err := Normalize(c); err == nil && n == norm {
			return action, true
		}
	}
	return "", false
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
