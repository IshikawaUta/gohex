package keymap

import "testing"

// FuzzChordParse fuzzes the shortcut compiler: any chord spelling must
// either parse to a canonical Chord or return an error, never panic.
func FuzzChordParse(f *testing.F) {
	f.Add("Ctrl+Shift+S")
	f.Add("ctrl+s")
	f.Add("Ctrl++")
	f.Add("Ctrl+")
	f.Add("")
	f.Add("+")
	f.Add("Alt+Gr+Enter")
	f.Add("NotAKey+Shift+Alt+1")
	f.Add("   Ctrl   +   F5   ")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			t.Skip("chord too long")
		}
		c, err := Parse(s)
		if err != nil {
			return
		}
		// A parsed chord must round-trip through its canonical form.
		again, err := Parse(c.String())
		if err != nil {
			t.Fatalf("Parse(%q) -> %q does not re-parse: %v", s, c.String(), err)
		}
		if again != c {
			t.Fatalf("Parse(%q) = %v, re-parse = %v", s, c, again)
		}
		if _, err := Normalize(s); err != nil {
			t.Fatalf("Normalize(%q): %v", s, err)
		}
	})
}

// FuzzKeymapValidate fuzzes full-keymap validation: one known action bound
// to a fuzzed chord, plus the chord as the lookup key.
func FuzzKeymapValidate(f *testing.F) {
	actions := Actions()
	if len(actions) == 0 {
		f.Skip("no actions registered")
	}
	action := actions[0]
	def := Default(action)
	f.Add(def)
	f.Add("Ctrl+Shift+Alt+F12")
	f.Add("")
	f.Add("bogus+key")
	f.Add(def + "+" + def)
	f.Fuzz(func(t *testing.T, chord string) {
		if len(chord) > 4096 {
			t.Skip("chord too long")
		}
		m := map[string]string{action: chord}
		_ = Validate(m)
		_, _ = Resolve(m, chord)
	})
}
