package config

import (
	"fmt"
	"strings"
)

// catalogKeys → translations. English is the source language; Indonesian
// (Bahasa Indonesia) mirrors it. The map structure accepts new languages
// without API changes.
var catalogs = map[string]map[string]string{
	"en": {
		"app.title":                "GoHex — Hex Editor & Digital Forensic Suite",
		"menu.file":                "File",
		"menu.file.open":           "Open…",
		"menu.file.save":           "Save",
		"menu.file.saveAs":         "Save As…",
		"menu.file.close":          "Close tab",
		"menu.edit":                "Edit",
		"menu.edit.undo":           "Undo",
		"menu.edit.redo":           "Redo",
		"menu.edit.cut":            "Cut",
		"menu.edit.copy":           "Copy",
		"menu.edit.paste":          "Paste",
		"menu.edit.fill":           "Fill selection…",
		"menu.search":              "Search",
		"menu.search.find":         "Find…",
		"menu.search.replace":      "Replace…",
		"menu.search.next":         "Find next",
		"menu.search.prev":         "Find previous",
		"menu.view":                "View",
		"menu.view.theme":          "Theme",
		"menu.view.encoding":       "Text encoding",
		"menu.view.columns":        "Bytes per line",
		"menu.help":                "Help",
		"menu.help.shortcuts":      "Keyboard shortcuts",
		"menu.help.about":          "About GoHex",
		"dialog.disclaimer.title":  "Legal disclaimer",
		"dialog.disclaimer.body":   "GoHex is for use only on systems and data you own or are authorized to examine. All operations are read-only by default; writing to physical disks requires an explicit flag, a two-step confirmation and is recorded in the audit log. No telemetry is collected.",
		"dialog.unsafeWrite.title": "Confirm disk write",
		"dialog.unsafeWrite.step1": "Step 1 of 2: you are about to write to a PHYSICAL DEVICE. This modifies evidence. Target: %s. Continue?",
		"dialog.unsafeWrite.step2": "Step 2 of 2: type the device name to confirm the irreversible write to %s.",
		"status.offset":            "Offset",
		"status.selection":         "Selection",
		"status.mode":              "Mode",
		"status.encoding":          "Encoding",
		"status.size":              "Size",
		"status.readOnly":          "Read-only",
		"status.editing":           "Editing",
		"goto.title":               "Go to offset",
		"goto.offset":              "Offset (hex, dec, +rel, e.g. 0x1A / 100 / +10 / 512s)",
		"search.title":             "Find",
		"search.hex":               "Hex pattern (supports ? wildcards)",
		"search.text":              "Text",
		"search.regex":             "Regular expression",
		"search.caseSensitive":     "Match case",
		"search.direction":         "Direction",
		"search.replaceWith":       "Replace with",
		"search.replaceAll":        "Replace all",
		"error.readFailed":         "Read failed",
		"error.saveFailed":         "Save failed",
		"error.outOfBounds":        "Offset is outside the file",
		"error.editNotAllowed":     "Editing is disabled in the read-only profile",
		"wizard.welcome":           "Welcome to GoHex",
		"wizard.step1":             "Step 1: choose your profile (Analyst, Recovery, Read-Only, Examiner)",
		"wizard.step2":             "Step 2: review security settings (audit log, write protection)",
		"wizard.step3":             "Step 3: pick a theme and language",
	},
	"id": {
		"app.title":                "GoHex — Editor Hex & Suite Forensik Digital",
		"menu.file":                "Berkas",
		"menu.file.open":           "Buka…",
		"menu.file.save":           "Simpan",
		"menu.file.saveAs":         "Simpan Sebagai…",
		"menu.file.close":          "Tutup tab",
		"menu.edit":                "Sunting",
		"menu.edit.undo":           "Batalkan",
		"menu.edit.redo":           "Ulangi",
		"menu.edit.cut":            "Potong",
		"menu.edit.copy":           "Salin",
		"menu.edit.paste":          "Tempel",
		"menu.edit.fill":           "Isi seleksi…",
		"menu.search":              "Cari",
		"menu.search.find":         "Cari…",
		"menu.search.replace":      "Ganti…",
		"menu.search.next":         "Cari berikutnya",
		"menu.search.prev":         "Cari sebelumnya",
		"menu.view":                "Tampilan",
		"menu.view.theme":          "Tema",
		"menu.view.encoding":       "Enkripsi teks",
		"menu.view.columns":        "Byte per baris",
		"menu.help":                "Bantuan",
		"menu.help.shortcuts":      "Pintasan papan ketik",
		"menu.help.about":          "Tentang GoHex",
		"dialog.disclaimer.title":  "Penafian hukum",
		"dialog.disclaimer.body":   "GoHex hanya untuk sistem dan data yang Anda miliki atau berwenang memeriksa. Semua operasi hanya-baca secara bawaan; menulis ke disk fisik memerlukan flag eksplisit, konfirmasi 2 langkah, dan dicatat di log audit. Tidak ada telemetri yang dikumpulkan.",
		"dialog.unsafeWrite.title": "Konfirmasi tulis disk",
		"dialog.unsafeWrite.step1": "Langkah 1 dari 2: Anda akan menulis ke PERANGKAT FISIK. Ini mengubah bukti. Target: %s. Lanjutkan?",
		"dialog.unsafeWrite.step2": "Langkah 2 dari 2: ketik nama perangkat untuk mengonfirmasi penulisan tak dapat dibatalkan ke %s.",
		"status.offset":            "Offset",
		"status.selection":         "Seleksi",
		"status.mode":              "Mode",
		"status.encoding":          "Enkoding",
		"status.size":              "Ukuran",
		"status.readOnly":          "Hanya-baca",
		"status.editing":           "Penyuntingan",
		"goto.title":               "Ke offset",
		"goto.offset":              "Offset (hex, des, +rel, mis. 0x1A / 100 / +10 / 512s)",
		"search.title":             "Cari",
		"search.hex":               "Pola hex (mendukung wildcard ?)",
		"search.text":              "Teks",
		"search.regex":             "Ekspresi reguler",
		"search.caseSensitive":     "Cocokkan huruf besar/kecil",
		"search.direction":         "Arah",
		"search.replaceWith":       "Ganti dengan",
		"search.replaceAll":        "Ganti semua",
		"error.readFailed":         "Gagal membaca",
		"error.saveFailed":         "Gagal menyimpan",
		"error.outOfBounds":        "Offset di luar berkas",
		"error.editNotAllowed":     "Penyuntingan dinonaktifkan di profil hanya-baca",
		"wizard.welcome":           "Selamat datang di GoHex",
		"wizard.step1":             "Langkah 1: pilih profil Anda (Analyst, Recovery, Read-Only, Examiner)",
		"wizard.step2":             "Langkah 2: periksa pengaturan keamanan (log audit, proteksi tulis)",
		"wizard.step3":             "Langkah 3: pilih tema dan bahasa",
	},
}

// Languages lists supported language codes.
func Languages() []string { return []string{"en", "id"} }

// T translates key into lang with English fallback, formatting any args.
func T(lang, key string, args ...any) string {
	cat, ok := catalogs[lang]
	if !ok {
		cat = catalogs["en"]
	}
	s, ok := cat[key]
	if !ok {
		s, ok = catalogs["en"][key]
		if !ok {
			return key // visible but harmless — never panic the UI
		}
	}
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}

// Catalog returns a copy of the translation catalog for lang with every
// English key present (language-specific entries override the fallback).
// The frontend loads it once at startup for synchronous lookups.
func Catalog(lang string) map[string]string {
	base := catalogs["en"]
	cat := catalogs[NormalizeLang(lang)]
	out := make(map[string]string, len(base)+len(cat))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range cat {
		out[k] = v
	}
	return out
}

// HasKey reports whether the key exists (for tests and tooling that verify
// catalog completeness across languages).
func HasKey(lang, key string) bool {
	cat, ok := catalogs[lang]
	if !ok {
		return false
	}
	_, ok = cat[key]
	return ok
}

// MissingKeys returns keys present in English but absent in lang — used by
// the i18n completeness test to prevent shipping untranslated UI.
func MissingKeys(lang string) []string {
	var missing []string
	for k := range catalogs["en"] {
		if !HasKey(lang, k) {
			missing = append(missing, k)
		}
	}
	return missing
}

// NormalizeLang maps a locale string ("id_ID.UTF-8", "en-US") to a catalog
// code, defaulting to "en".
func NormalizeLang(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "en"
	}
	if strings.HasPrefix(s, "id") {
		return "id"
	}
	return "en"
}
