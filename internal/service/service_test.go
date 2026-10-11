package service

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/config"
)

// newTestApp builds a service isolated from the user's real config/audit.
func newTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GOHEX_AUDIT_LOG", filepath.Join(dir, "audit.jsonl"))
	app, err := New(filepath.Join(dir, "config.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	return app
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOpenReadInfo(t *testing.T) {
	app := newTestApp(t)
	data := bytes.Repeat([]byte("0123456789ABCDEF"), 64) // 1 KiB
	p := writeFile(t, "evidence.bin", data)

	info, err := app.OpenFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size != int64(len(data)) || info.Path != p {
		t.Fatalf("info = %+v", info)
	}
	if !info.EditingAllowed || info.Profile != config.ProfileAnalyst {
		t.Fatalf("profile = %+v", info)
	}
	if info.Name != "evidence.bin" || info.Encoding != "ASCII" {
		t.Fatalf("name/enc = %q %q", info.Name, info.Encoding)
	}

	// Windowed read returns bytes + decoded text.
	wd, err := app.ReadWindow(info.ID, 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wd.Bytes, data[16:48]) {
		t.Fatalf("window bytes mismatch: %x", wd.Bytes)
	}
	if wd.Text == "" || wd.Offset != 16 {
		t.Fatalf("window text = %q offset %d", wd.Text, wd.Offset)
	}
	// Read past the end → empty, no error.
	wd, err = app.ReadWindow(info.ID, 1<<30, 32)
	if err != nil || len(wd.Bytes) != 0 {
		t.Fatalf("past end: %v %d", err, len(wd.Bytes))
	}
	// Oversized length clamps to the file size.
	wd, err = app.ReadWindow(info.ID, 0, 1<<40)
	if err != nil || len(wd.Bytes) != 1024 {
		t.Fatalf("clamp to file size: %d", len(wd.Bytes))
	}

	list := app.ListDocuments()
	if len(list) != 1 || list[0].ID != info.ID {
		t.Fatalf("list = %+v", list)
	}
	if err := app.CloseDocument(info.ID); err != nil {
		t.Fatal(err)
	}
	if len(app.ListDocuments()) != 0 {
		t.Fatal("close failed")
	}
	if err := app.CloseDocument(99); err == nil {
		t.Fatal("closing unknown doc should fail")
	}
}

func TestAuditRecordsOpen(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "a.bin", []byte("hello"))
	if _, err := app.OpenFile(p); err != nil {
		t.Fatal(err)
	}
	events, err := audit.ReadAll(app.log.Path(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[0].Action != audit.ActionOpen || events[0].Target != p {
		t.Fatalf("events = %+v", events)
	}
}

func TestEditUndoRedo(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "edit.bin", []byte("AAAA"))
	info, err := app.OpenFile(p)
	if err != nil {
		t.Fatal(err)
	}

	if err := app.WriteBytes(info.ID, 0, []byte("BB")); err != nil {
		t.Fatal(err)
	}
	if err := app.InsertBytes(info.ID, 4, []byte("CC")); err != nil {
		t.Fatal(err)
	}
	if err := app.DeleteRange(info.ID, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := app.FillRange(info.ID, 0, 2, 'Z'); err != nil {
		t.Fatal(err)
	}
	wd, _ := app.ReadWindow(info.ID, 0, 6)
	if string(wd.Bytes) != "ZZACC" {
		t.Fatalf("after edits = %q", wd.Bytes)
	}
	cur, _ := app.DocumentInfo(info.ID)
	if !cur.Dirty || !cur.CanUndo || cur.Version == 0 {
		t.Fatalf("state = %+v", cur)
	}
	// Undo chain back to the original.
	for i := 0; i < 4; i++ {
		if _, err := app.Undo(info.ID); err != nil {
			t.Fatalf("undo %d: %v", i, err)
		}
	}
	wd, _ = app.ReadWindow(info.ID, 0, 4)
	if string(wd.Bytes) != "AAAA" {
		t.Fatalf("after undo = %q", wd.Bytes)
	}
	if _, err := app.Redo(info.ID); err != nil {
		t.Fatal(err)
	}
	// Bounds errors surface.
	if err := app.WriteBytes(info.ID, 100, []byte("X")); err == nil {
		t.Fatal("write out of bounds should fail")
	}
	// Undo may still have history; the error is fine to ignore.
	_, _ = app.Undo(info.ID)
}

func TestReadOnlyProfileDeniesEdits(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "ro.bin", []byte("DATA"))
	info, err := app.OpenFile(p)
	if err != nil {
		t.Fatal(err)
	}
	prefs := app.Preferences()
	prefs.Profile = config.ProfileReadOnly
	if err := app.SetPreferences(prefs); err != nil {
		t.Fatal(err)
	}

	if err := app.WriteBytes(info.ID, 0, []byte("X")); err == nil {
		t.Fatal("write must be denied in read-only profile")
	}
	if err := app.InsertBytes(info.ID, 0, []byte("X")); err == nil {
		t.Fatal("insert must be denied")
	}
	if err := app.DeleteRange(info.ID, 0, 1); err == nil {
		t.Fatal("delete must be denied")
	}
	if err := app.FillRange(info.ID, 0, 1, 0); err == nil {
		t.Fatal("fill must be denied")
	}
	if _, err := app.Undo(info.ID); err == nil {
		t.Fatal("undo must be denied")
	}
	if _, err := app.Save(info.ID); err == nil {
		t.Fatal("save must be denied")
	}
	// The denial is audited as a config/profile state; ensure prefs recorded.
	events, _ := audit.ReadAll(app.log.Path(), nil)
	found := false
	for _, e := range events {
		if e.Action == audit.ActionConfig {
			found = true
		}
	}
	if !found {
		t.Fatalf("config change not audited: %+v", events)
	}
}

func TestSaveInPlaceAndRewrite(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "save.bin", bytes.Repeat([]byte{0x11}, 4096))
	info, _ := app.OpenFile(p)

	// Overwrite-only → in-place.
	if err := app.WriteBytes(info.ID, 100, []byte{0xAA, 0xBB, 0xCC}); err != nil {
		t.Fatal(err)
	}
	res, err := app.Save(info.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "in-place" || res.BytesSaved != 3 {
		t.Fatalf("save = %+v", res)
	}
	if res.SHA256 == "" {
		t.Fatal("small save should record sha256")
	}
	onDisk, _ := os.ReadFile(p)
	if !bytes.Equal(onDisk[100:103], []byte{0xAA, 0xBB, 0xCC}) {
		t.Fatalf("disk bytes = %x", onDisk[100:103])
	}
	cur, _ := app.DocumentInfo(info.ID)
	if cur.Dirty {
		t.Fatal("clean after save")
	}

	// Structural edit → full rewrite.
	if err := app.InsertBytes(info.ID, 0, []byte{0xDE, 0xAD}); err != nil {
		t.Fatal(err)
	}
	if err := app.DeleteRange(info.ID, 0, 1); err != nil {
		t.Fatal(err)
	}
	res, err = app.Save(info.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "rewrite" {
		t.Fatalf("save mode = %s", res.Mode)
	}
	onDisk, _ = os.ReadFile(p)
	if int64(len(onDisk)) != 4097 {
		t.Fatalf("rewritten size = %d", len(onDisk))
	}
	if onDisk[0] != 0xAD {
		t.Fatalf("rewritten head = %x", onDisk[:2])
	}
}

func TestSaveAsAndNewDocument(t *testing.T) {
	app := newTestApp(t)
	info := app.NewDocument()
	if _, err := app.Save(info.ID); err == nil {
		t.Fatal("save without path must fail")
	}
	out := filepath.Join(t.TempDir(), "out.bin")
	if err := app.InsertBytes(info.ID, 0, []byte("fresh content")); err != nil {
		t.Fatal(err)
	}
	res, err := app.SaveAs(info.ID, out)
	if err != nil {
		t.Fatal(err)
	}
	if res.BytesSaved != 13 {
		t.Fatalf("saved %d bytes", res.BytesSaved)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "fresh content" {
		t.Fatalf("file = %q", got)
	}
	// Rebound path.
	cur, _ := app.DocumentInfo(info.ID)
	if cur.Path != out || cur.Dirty {
		t.Fatalf("rebound = %+v", cur)
	}
	events, _ := audit.ReadAll(app.log.Path(), nil)
	found := false
	for _, e := range events {
		if e.Action == audit.ActionSaveAs && e.Target == out {
			found = true
		}
	}
	if !found {
		t.Fatal("SaveAs not audited")
	}
}

func TestSandboxMode(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "sandbox.bin", []byte("ORIGINAL"))
	info, _ := app.OpenFile(p)
	prefs := app.Preferences()
	prefs.SandboxMode = true
	if err := app.SetPreferences(prefs); err != nil {
		t.Fatal(err)
	}
	if err := app.WriteBytes(info.ID, 0, []byte("CHANGED!")); err != nil {
		t.Fatal(err)
	}
	res, err := app.Save(info.ID)
	if err != nil || res.Mode != "sandbox" {
		t.Fatalf("save = %+v, %v", res, err)
	}
	onDisk, _ := os.ReadFile(p)
	if string(onDisk) != "ORIGINAL" {
		t.Fatalf("sandbox must not touch disk: %q", onDisk)
	}
	events, _ := audit.ReadAll(app.log.Path(), nil)
	sandboxLogged := false
	for _, e := range events {
		if e.Action == audit.ActionSave && e.Detail["sandbox"] == "true" {
			sandboxLogged = true
		}
	}
	if !sandboxLogged {
		t.Fatal("sandbox save not audited")
	}
}

func TestFindFlow(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "find.bin", []byte("abcXXdefXXghiXX"))
	info, _ := app.OpenFile(p)

	// Single next from cursor.
	res, err := app.Find(FindRequest{ID: info.ID, Mode: "text", Pattern: "XX", Direction: "next", From: 0})
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 1 || res.Matches[0].Start != 3 {
		t.Fatalf("next = %+v", res)
	}
	// Single prev: nearest match before offset 10 is at 8.
	res, err = app.Find(FindRequest{ID: info.ID, Mode: "text", Pattern: "XX", Direction: "prev", From: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 1 || res.Matches[0].Start != 8 {
		t.Fatalf("prev = %+v", res)
	}
	// Wrap next past the end.
	res, err = app.Find(FindRequest{ID: info.ID, Mode: "hex", Pattern: "58 58", Direction: "next", From: 15, Wrap: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 1 || res.Matches[0].Start != 3 {
		t.Fatalf("wrap next = %+v", res)
	}
	// Find-all with truncation flag.
	res, err = app.Find(FindRequest{ID: info.ID, Mode: "hex", Pattern: "58 58", Direction: "next", From: 0, Max: 2})
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 2 || !res.Truncated {
		t.Fatalf("find all = %+v", res)
	}
	// Regex mode.
	res, err = app.Find(FindRequest{ID: info.ID, Mode: "regex", Pattern: `[a-z]+X`, Direction: "next", From: 0, Max: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.Count == 0 {
		t.Fatal("regex find found nothing")
	}
	// Bad inputs.
	if _, err := app.Find(FindRequest{ID: info.ID, Mode: "hex", Pattern: "zz"}); err == nil {
		t.Fatal("bad hex pattern should fail")
	}
	if _, err := app.Find(FindRequest{ID: info.ID, Mode: "wat", Pattern: "x"}); err == nil {
		t.Fatal("bad mode should fail")
	}
	if _, err := app.Find(FindRequest{ID: 42, Mode: "hex", Pattern: "00"}); err == nil {
		t.Fatal("unknown doc should fail")
	}
}

func TestReplaceAllGuard(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "rep.bin", []byte("aXaXa"))
	info, _ := app.OpenFile(p)

	if _, err := app.ReplaceAll(info.ID, "text", "X", "YY", "ASCII", false, false); err == nil {
		t.Fatal("replace without confirmation must fail")
	}
	n, err := app.ReplaceAll(info.ID, "text", "X", "YY", "ASCII", false, true)
	if err != nil || n != 2 {
		t.Fatalf("replace n=%d err=%v", n, err)
	}
	wd, _ := app.ReadWindow(info.ID, 0, 9)
	if string(wd.Bytes) != "aYYaYYa" {
		t.Fatalf("replaced = %q", wd.Bytes)
	}
	// Hex replacement: literal bytes of "YY" (59 59) -> 5A.
	n, err = app.ReplaceAll(info.ID, "hex", "59 59", "5A", "", false, true)
	if err != nil || n != 2 {
		t.Fatalf("hex replace n=%d err=%v", n, err)
	}
	wd, _ = app.ReadWindow(info.ID, 0, 9)
	if string(wd.Bytes) != "aZaZa" {
		t.Fatalf("hex replaced = %q", wd.Bytes)
	}
}

func TestHashDocument(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "hash.bin", []byte("abc"))
	info, _ := app.OpenFile(p)
	sum, err := app.HashDocument(info.ID, "sha256", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sum, "SHA-256:") || !strings.Contains(sum, "ba7816bf") {
		t.Fatalf("sum = %q", sum)
	}
	// Selection hash.
	app.SetSelection(info.ID, 0, 1)
	sum, err = app.HashDocument(info.ID, "md5", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sum, "0cc175b9") { // md5("a")
		t.Fatalf("sel sum = %q", sum)
	}
	// Empty selection.
	app.SetSelection(info.ID, 0, 0)
	if _, err := app.HashDocument(info.ID, "md5", true); err == nil {
		t.Fatal("empty selection should fail")
	}
	if _, err := app.HashDocument(info.ID, "nope", false); err == nil {
		t.Fatal("bad algo should fail")
	}
	// Audited.
	events, _ := audit.ReadAll(app.log.Path(), nil)
	found := false
	for _, e := range events {
		if e.Action == audit.ActionHashVerify && e.Hash != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("hash not audited")
	}
}

func TestGotoAndSelection(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "nav.bin", bytes.Repeat([]byte{0}, 4096))
	info, _ := app.OpenFile(p)

	off, err := app.Goto(info.ID, "0x100")
	if err != nil || off != 0x100 {
		t.Fatalf("goto hex = %d, %v", off, err)
	}
	off, err = app.Goto(info.ID, "+10")
	if err != nil || off != 0x110 {
		t.Fatalf("goto rel = %#x, %v", off, err)
	}
	off, err = app.Goto(info.ID, "2s") // sectors of 512
	if err != nil || off != 1024 {
		t.Fatalf("goto sector = %d, %v", off, err)
	}
	if _, err := app.Goto(info.ID, "zz"); err == nil {
		t.Fatal("bad expr should fail")
	}
	// Out-of-range clamps.
	off, _ = app.Goto(info.ID, "0xFFFFFF")
	if off != 4096 {
		t.Fatalf("clamp = %d", off)
	}

	if err := app.SetSelection(info.ID, 100, 50); err != nil {
		t.Fatal(err)
	}
	cur, _ := app.DocumentInfo(info.ID)
	if cur.SelStart != 50 || cur.SelEnd != 100 || cur.Cursor != 50 {
		t.Fatalf("selection = %+v", cur)
	}
	// Negative/oversized selection clamps.
	app.SetSelection(info.ID, -5, 1<<40)
	cur, _ = app.DocumentInfo(info.ID)
	if cur.SelStart != 0 || cur.SelEnd != 4096 {
		t.Fatalf("clamp selection = %+v", cur)
	}
}

func TestEncodingSwitchAndConverters(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "enc.bin", []byte{0xC8, 0x89}) // EBCDIC "Hi"
	info, _ := app.OpenFile(p)
	if err := app.SetEncoding(info.ID, "EBCDIC"); err != nil {
		t.Fatal(err)
	}
	wd, _ := app.ReadWindow(info.ID, 0, 2)
	if wd.Text != "Hi" {
		t.Fatalf("ebcdic text = %q", wd.Text)
	}
	if err := app.SetEncoding(info.ID, "Klingon"); err == nil {
		t.Fatal("bad encoding should fail")
	}
	if err := app.SetEncoding(42, "EBCDIC"); err == nil {
		t.Fatal("unknown doc")
	}

	txt, err := app.ConvertHexToText("48 69", "ASCII")
	if err != nil || txt != "Hi" {
		t.Fatalf("hex→text = %q, %v", txt, err)
	}
	hx, err := app.ConvertTextToHex("Hi", "ASCII")
	if err != nil || hx != "48 69" {
		t.Fatalf("text→hex = %q, %v", hx, err)
	}
	if _, err := app.ConvertHexToText("zz", "ASCII"); err == nil {
		t.Fatal("bad hex should fail")
	}
	if _, err := app.ConvertTextToHex("x", "nope"); err == nil {
		t.Fatal("bad enc should fail")
	}

	ihex := ":020000040000FA\n:0400000001020304F2\n:00000001FF\n"
	data, origin, err := app.ConvertIntelHex(ihex)
	if err != nil || origin != 0 || !bytes.Equal(data, []byte{1, 2, 3, 4}) {
		t.Fatalf("ihex = %x @%d, %v", data, origin, err)
	}
	if _, _, err := app.ConvertIntelHex("garbage"); err == nil {
		t.Fatal("bad ihex should fail")
	}
	srec := "S00600004844521B\nS1130000000102030405060708090A0B0C0D0E0F74\nS9030000FC\n"
	data, _, err = app.ConvertSRecords(srec)
	if err != nil || len(data) == 0 {
		t.Fatalf("srec = %x, %v", data, err)
	}
	if _, _, err := app.ConvertSRecords("garbage"); err == nil {
		t.Fatal("bad srec should fail")
	}
}

func TestPreferencesRoundTripAndTranslate(t *testing.T) {
	app := newTestApp(t)
	p := app.Preferences()
	p.Theme = config.ThemeLight
	p.Language = "id"
	if err := app.SetPreferences(p); err != nil {
		t.Fatal(err)
	}
	if got := app.Preferences(); got.Theme != config.ThemeLight || got.Language != "id" {
		t.Fatalf("prefs = %+v", got)
	}
	invalid := app.Preferences()
	invalid.Profile = "nope"
	if err := app.SetPreferences(invalid); err == nil {
		t.Fatal("invalid prefs should fail")
	}
	if app.Version() == "" {
		t.Fatal("version empty")
	}
	if app.Translate("id", "menu.file.open") != "Buka…" {
		t.Fatal("translate")
	}
	// Disclaimer follows the active language ("id" was set above); check
	// language-neutral content, then the EN variant explicitly.
	d := app.Disclaimer()
	if len(d) < 50 || !strings.Contains(d, "audit") {
		t.Fatalf("disclaimer = %q", d)
	}
	p = app.Preferences()
	p.Language = "en"
	if err := app.SetPreferences(p); err != nil {
		t.Fatal(err)
	}
	if d = app.Disclaimer(); !strings.Contains(d, "read-only by default") {
		t.Fatalf("en disclaimer = %q", d)
	}
	if !app.EditingAllowed() {
		t.Fatal("editing should be allowed by default")
	}
}

func TestStat(t *testing.T) {
	app := newTestApp(t)
	p := writeFile(t, "meta.bin", []byte("123"))
	fi, err := app.Stat(p)
	if err != nil || fi.Size != 3 || fi.IsDir {
		t.Fatalf("stat = %+v, %v", fi, err)
	}
	if _, err := app.Stat(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing stat should fail")
	}
}

func TestUnknownDocumentErrors(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.DocumentInfo(7); err == nil {
		t.Fatal("missing doc info")
	}
	if _, err := app.ReadWindow(7, 0, 1); err == nil {
		t.Fatal("missing doc read")
	}
	if err := app.SetSelection(7, 0, 0); err == nil {
		t.Fatal("missing doc selection")
	}
	if _, err := app.Goto(7, "0"); err == nil {
		t.Fatal("missing doc goto")
	}
	if err := app.SetEncoding(7, "ASCII"); err == nil {
		t.Fatal("missing doc encoding")
	}
	if _, err := app.HashDocument(7, "md5", false); err == nil {
		t.Fatal("missing doc hash")
	}
	if _, err := app.Save(7); err == nil {
		t.Fatal("missing doc save")
	}
	if _, err := app.SaveAs(7, "x"); err == nil {
		t.Fatal("missing doc save as")
	}
}

func TestShortcutDefaults(t *testing.T) {
	app := newTestApp(t)
	d := app.ShortcutDefaults()
	if d["file.open"] != "Ctrl+O" || d["search.find"] != "Ctrl+F" {
		t.Fatalf("defaults = %v", d)
	}
	if len(d) < 10 {
		t.Fatalf("defaults too small: %d", len(d))
	}
	// Saving a preferences object with the defaults must validate.
	p := config.Default()
	if err := app.SetPreferences(p); err != nil {
		t.Fatalf("SetPreferences(defaults): %v", err)
	}
}
