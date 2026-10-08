package browser

import (
	"os"
	"path/filepath"
	"testing"
)

// plant creates a file (and its parents) under a temporary home directory.
func plant(t *testing.T, home, rel string) string {
	t.Helper()
	path := filepath.Join(home, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiscoverLinux(t *testing.T) {
	home := t.TempDir()
	plant(t, home, ".config/google-chrome/Default/History")
	plant(t, home, ".config/google-chrome/Profile 1/History")
	plant(t, home, ".config/chromium/Default/History")
	// A directory that is not a profile must be ignored.
	plant(t, home, ".config/google-chrome/ShaderCache/blob")
	// Firefox: profile folders hold places.sqlite one level down.
	plant(t, home, ".mozilla/firefox/aaaa1111.default-release/places.sqlite")
	plant(t, home, ".mozilla/firefox/crashes/submitted/notes.txt")
	// The Flatpak sandbox keeps its own copy.
	plant(t, home, ".var/app/org.mozilla.firefox/.mozilla/firefox/bbbb2222.default/places.sqlite")

	got, err := discover(home, "linux")
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, p := range got {
		d, err := filepath.Rel(home, p.Dir)
		if err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, filepath.ToSlash(d))
	}
	want := []string{
		".config/chromium/Default",
		".config/google-chrome/Default",
		".config/google-chrome/Profile 1",
		".mozilla/firefox/aaaa1111.default-release",
		".var/app/org.mozilla.firefox/.mozilla/firefox/bbbb2222.default",
	}
	if len(dirs) != len(want) {
		t.Fatalf("found %v, want %v", dirs, want)
	}
	for i := range want {
		if dirs[i] != want[i] {
			t.Errorf("profile %d = %q, want %q", i, dirs[i], want[i])
		}
	}
	// Every reported directory really holds that browser's marker file.
	for _, p := range got {
		if !isFile(filepath.Join(p.Dir, p.Browser.marker())) {
			t.Errorf("%s has no %s marker", p.Dir, p.Browser.marker())
		}
	}
}

func TestDiscoverDarwin(t *testing.T) {
	home := t.TempDir()
	plant(t, home, "Library/Safari/History.db")
	plant(t, home, "Library/Application Support/Google/Chrome/Default/History")
	// macOS nests profiles under Firefox/Profiles.
	plant(t, home, "Library/Application Support/Firefox/Profiles/cccc3333.default/places.sqlite")

	got, err := discover(home, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	// Chrome, then Firefox, then Safari: the result is sorted by browser.
	kinds := map[Browser]int{}
	for _, p := range got {
		kinds[p.Browser]++
	}
	if kinds[Chrome] != 1 || kinds[Firefox] != 1 || kinds[Safari] != 1 {
		t.Fatalf("found %+v, want one profile per browser", kinds)
	}
	for _, p := range got {
		if p.Browser == Safari && p.Name != "Safari" {
			t.Errorf("Safari profile name = %q, want %q", p.Name, "Safari")
		}
		if p.Browser == Firefox && filepath.Base(p.Dir) != "cccc3333.default" {
			t.Errorf("Firefox profile dir = %q", p.Dir)
		}
	}
}

func TestDiscoverWindows(t *testing.T) {
	home := t.TempDir()
	plant(t, home, "AppData/Local/Google/Chrome/User Data/Default/History")
	plant(t, home, "AppData/Local/Microsoft/Edge/User Data/Profile 2/History")
	plant(t, home, "AppData/Roaming/Mozilla/Firefox/Profiles/dddd4444.default/places.sqlite")

	got, err := discover(home, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("found %d profiles, want 3", len(got))
	}
	if got[1].Name != "Profile 2" || got[1].Browser != Chrome {
		t.Errorf("second profile = %+v, want Edge Profile 2", got[1])
	}
	if got[2].Browser != Firefox {
		t.Errorf("third profile = %+v, want Firefox", got[2])
	}
}

func TestDiscoverEmptyHome(t *testing.T) {
	got, err := discover(t.TempDir(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("found %d profiles in an empty home", len(got))
	}
	// An unsupported platform reports nothing rather than guessing.
	got, err = discover(t.TempDir(), "plan9")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("plan9 returned %d profiles", len(got))
	}
}

func TestUniqueProfiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "chrome")
	in := []Profile{
		{Browser: Chrome, Name: "Default", Dir: dir},
		{Browser: Chrome, Name: "Default", Dir: dir},
		{Browser: Chrome, Name: "Profile 1", Dir: dir + string(filepath.Separator) + "Profile 1"},
	}
	got := uniqueProfiles(in)
	if len(got) != 2 {
		t.Fatalf("uniqueProfiles returned %d entries, want 2", len(got))
	}
	if got[0].Dir != dir || got[1].Name != "Profile 1" {
		t.Errorf("uniqueProfiles = %+v, want the first of each", got)
	}
}

func TestDiscoverMissingHome(t *testing.T) {
	// A relative path that does not exist yields no profiles and no error:
	// "nothing installed here" is a normal answer, not a failure.
	got, err := discover(filepath.Join(t.TempDir(), "nope"), "linux")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("found %d profiles below a missing directory", len(got))
	}
}
