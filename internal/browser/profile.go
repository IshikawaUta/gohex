package browser

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// marker is the file that proves a directory is a profile of a given
// browser. Discovery is driven by the marker rather than by a hard-coded
// profile list so profiles the user created, copied or renamed are still
// found.
func (b Browser) marker() string {
	switch b {
	case Chrome:
		return "History"
	case Firefox:
		return "places.sqlite"
	case Safari:
		return "History.db"
	}
	return ""
}

// root is one well-known location that may contain profiles of a browser.
type root struct {
	browser Browser
	rel     string
}

// roots lists the profile containers for every supported platform. Paths are
// always expressed with forward slashes and joined onto the caller's home
// directory, so a Windows home laid out for examination can be scanned from
// any host.
func roots(goos string) []root {
	var out []root
	add := func(b Browser, rel string) {
		out = append(out, root{browser: b, rel: rel})
	}
	switch goos {
	case "windows":
		add(Chrome, "AppData/Local/Google/Chrome/User Data")
		add(Chrome, "AppData/Local/Chromium/User Data")
		add(Chrome, "AppData/Local/Microsoft/Edge/User Data")
		add(Chrome, "AppData/Local/BraveSoftware/Brave-Browser/User Data")
		add(Firefox, "AppData/Roaming/Mozilla/Firefox")
	case "darwin":
		add(Chrome, "Library/Application Support/Google/Chrome")
		add(Chrome, "Library/Application Support/Chromium")
		add(Chrome, "Library/Application Support/Microsoft Edge")
		add(Chrome, "Library/Application Support/BraveSoftware/Brave-Browser")
		add(Firefox, "Library/Application Support/Firefox")
		add(Safari, "Library/Safari")
	default: // linux and the BSDs
		add(Chrome, ".config/google-chrome")
		add(Chrome, ".config/chromium")
		add(Chrome, ".config/microsoft-edge")
		add(Chrome, ".config/BraveSoftware/Brave-Browser")
		add(Firefox, ".mozilla/firefox")
		add(Firefox, ".var/app/org.mozilla.firefox/.mozilla/firefox")
	}
	return out
}

// Discover lists the browser profiles rooted at home for the operating
// system this binary runs on. An empty home falls back to the current user's
// own home directory. The result is empty, not an error, when nothing is
// installed.
func Discover(home string) ([]Profile, error) {
	return discover(home, runtime.GOOS)
}

// discover is Discover with the platform injected so every layout can be
// tested on any host.
func discover(home, goos string) ([]Profile, error) {
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		home = h
	}
	var found []Profile
	for _, r := range roots(goos) {
		dir := filepath.Join(home, filepath.FromSlash(r.rel))
		found = append(found, r.browser.findProfiles(dir)...)
	}
	out := uniqueProfiles(found)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Browser != out[j].Browser {
			return out[i].Browser < out[j].Browser
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Dir < out[j].Dir
	})
	return out, nil
}

// uniqueProfiles removes profiles already seen, keyed by their directory.
// Two roots can name the same folder — a distribution that symlinks one
// browser's config into another's would do exactly that — and reporting a
// profile twice would double every artifact in the report.
func uniqueProfiles(in []Profile) []Profile {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, p := range in {
		key := filepath.Clean(p.Dir)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

// maxProfileDepth is how far below a container the reader looks for a
// marker. Two levels cover the layouts in roots() — for example
// Firefox/Profiles/<name> — while staying shallow enough to walk quickly.
const maxProfileDepth = 2

// findProfiles returns every directory at or below dir that holds this
// browser's marker. The container itself is included so a browser that keeps
// its database next to everything else (Safari) is found too.
func (b Browser) findProfiles(dir string) []Profile {
	var out []Profile
	mark := b.marker()
	var walk func(cur string, depth int)
	walk = func(cur string, depth int) {
		if isFile(filepath.Join(cur, mark)) {
			out = append(out, Profile{Browser: b, Name: filepath.Base(cur), Dir: cur})
			return // a marker identifies a leaf profile; do not descend into it
		}
		if depth == maxProfileDepth {
			return
		}
		entries, err := os.ReadDir(cur)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			walk(filepath.Join(cur, e.Name()), depth+1)
		}
	}
	walk(dir, 0)
	return out
}

func isFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}
