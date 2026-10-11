package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPlaintextLogRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = l.Log(Event{
		Action: ActionOpen,
		Target: "/evidence/disk.dd",
		Result: ResultOK,
		Detail: map[string]string{"mode": "read-only"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Log(Event{
		Time:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		User:   "examiner1",
		Action: ActionWriteDisk,
		Target: "/dev/sdX",
		Result: ResultDenied,
		Hash:   "abc123",
	}); err != nil {
		t.Fatal(err)
	}
	if l.Path() != p {
		t.Fatalf("path = %q", l.Path())
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Log(Event{Action: ActionSave}); err == nil {
		t.Fatal("log after close should fail")
	}
	if err := l.Close(); err != nil {
		t.Fatal("double close should be a no-op")
	}

	events, err := ReadAll(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d", len(events))
	}
	if events[0].Action != ActionOpen || events[0].Result != ResultOK {
		t.Fatalf("event0 = %+v", events[0])
	}
	if events[0].Time.IsZero() {
		t.Error("auto timestamp missing")
	}
	if events[0].Detail["mode"] != "read-only" {
		t.Error("detail missing")
	}
	if events[1].User != "examiner1" || !events[1].Time.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("event1 = %+v", events[1])
	}
	if events[1].Hash != "abc123" {
		t.Error("hash field missing")
	}
}

func TestEncryptedLogRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit-enc.jsonl")
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	l, err := Open(p, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Log(Event{Action: ActionHashVerify, Target: "x.bin", Result: ResultOK}); err != nil {
		t.Fatal(err)
	}
	l.Close()

	// Raw file must not contain plaintext.
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "hash_verify") {
		t.Fatal("ciphertext leaked plaintext action name")
	}

	events, err := ReadAll(p, key)
	if err != nil || len(events) != 1 || events[0].Action != ActionHashVerify {
		t.Fatalf("decrypt read = %+v, %v", events, err)
	}
	if _, err := ReadAll(p, []byte("wrong")); err == nil {
		t.Fatal("wrong key length should fail")
	}
	wrong := make([]byte, KeySize)
	if _, err := ReadAll(p, wrong); err == nil {
		t.Fatal("wrong key should fail decryption")
	}
}

func TestPassphraseLog(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit-pass.jsonl")
	l, err := OpenWithPassphrase(p, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Log(Event{Action: ActionCase, Target: "CASE-1", Result: ResultOK}); err != nil {
		t.Fatal(err)
	}
	l.Close()

	// Reopen with the same passphrase appends.
	l2, err := OpenWithPassphrase(p, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Log(Event{Action: ActionCase, Target: "CASE-2", Result: ResultOK}); err != nil {
		t.Fatal(err)
	}
	l2.Close()

	events, err := ReadAllPassphrase(p, "correct horse battery staple")
	if err != nil || len(events) != 2 {
		t.Fatalf("events = %d, %v", len(events), err)
	}
	if _, err := ReadAllPassphrase(p, "wrong passphrase"); err == nil {
		t.Fatal("wrong passphrase should fail")
	}
}

func TestOpenErrors(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "nope", "deep", "x.log"), nil); err == nil {
		t.Error("missing dir should fail")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "x.log"), []byte("short")); !errors.Is(err, ErrNoKey) {
		t.Errorf("short key = %v", err)
	}
	if _, err := ReadAll(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Error("missing log read should fail")
	}
}

func TestKeyFromPassphrase(t *testing.T) {
	salt := NewSalt()
	k1, err := KeyFromPassphrase("pw", salt)
	if err != nil || len(k1) != KeySize {
		t.Fatalf("derive = %v, %v", len(k1), err)
	}
	k2, _ := KeyFromPassphrase("pw", salt)
	if string(k1) != string(k2) {
		t.Fatal("derivation must be deterministic")
	}
	k3, _ := KeyFromPassphrase("other", salt)
	if string(k1) == string(k3) {
		t.Fatal("different passphrase must differ")
	}
	if _, err := KeyFromPassphrase("pw", []byte{1}); err == nil {
		t.Fatal("bad salt length should fail")
	}
}

func TestNoopLogger(t *testing.T) {
	l := Noop()
	if err := l.Log(Event{Action: ActionOpen}); err != nil {
		t.Fatal(err)
	}
	l.Close()
}

func TestUserFallback(t *testing.T) {
	// currentUser reads USER/USERNAME env; both may be set in CI.
	if currentUser() == "" {
		t.Fatal("currentUser should never be empty")
	}
}
