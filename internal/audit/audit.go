// Package audit implements the GoHex audit trail: an append-only JSON Lines
// log recording every file open, save, export and (explicitly authorized)
// physical-disk write. Logs can optionally be encrypted with AES-256-GCM so
// that sensitive casework metadata is protected at rest.
package audit

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Action identifies the kind of recorded operation.
type Action string

// Recorded actions. Any future write-capable feature MUST add its action
// here and log it (see docs/security.md).
const (
	ActionOpen       Action = "open" // opened a file/image/evidence
	ActionSave       Action = "save" // saved a document
	ActionSaveAs     Action = "save_as"
	ActionExport     Action = "export"      // exported data/reports
	ActionImport     Action = "import"      // imported evidence into a case
	ActionHashVerify Action = "hash_verify" // computed/verified a hash
	ActionWriteDisk  Action = "write_disk"  // physical disk/partition write
	ActionProfile    Action = "profile"     // profile or permission change
	ActionConfig     Action = "config"      // settings that affect security
	ActionCase       Action = "case"        // case lifecycle
	ActionSearch     Action = "search"      // search over evidence (access record)
	ActionScript     Action = "script"      // ran an automation script over evidence
)

// Result of the operation.
const (
	ResultOK       = "ok"
	ResultDenied   = "denied"
	ResultError    = "error"
	ResultCanceled = "canceled"
)

// Event is one audit record. It serialises as a single JSON object per line.
type Event struct {
	Time   time.Time         `json:"ts"`
	User   string            `json:"user"`
	Action Action            `json:"action"`
	Target string            `json:"target"`
	Result string            `json:"result"`
	Hash   string            `json:"hash,omitempty"`
	Detail map[string]string `json:"detail,omitempty"`
}

// Logger appends events to a JSONL file, optionally encrypting each line.
// It is safe for concurrent use.
type Logger struct {
	mu     sync.Mutex
	f      *os.File
	gcm    cipher.AEAD
	path   string
	closed bool
	syncOK bool
}

// KeySize is the required AES-256 key length in bytes.
const KeySize = 32

// saltSize and scrypt parameters for passphrase-derived keys.
const (
	saltSize = 16
	scryptN  = 1 << 15
	scryptR  = 8
	scryptP  = 1
)

// ErrNoKey is returned when a caller passes a wrong-length key.
var ErrNoKey = errors.New("audit: encryption key must be 32 bytes")

// KeyFromPassphrase derives a 32-byte AES key from a passphrase and salt.
// Callers must store the salt alongside the log (OpenWithPassphrase embeds
// it as the first line).
func KeyFromPassphrase(passphrase string, salt []byte) ([]byte, error) {
	if len(salt) != saltSize {
		return nil, fmt.Errorf("audit: salt must be %d bytes", saltSize)
	}
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, KeySize)
	if err != nil {
		return nil, fmt.Errorf("audit: derive key: %w", err)
	}
	return key, nil
}

// NewSalt returns a fresh random salt for KeyFromPassphrase.
func NewSalt() []byte {
	s := make([]byte, saltSize)
	rand.Read(s) //nolint:errcheck // crypto/rand never fails on supported platforms
	return s
}

// Open opens (creating if needed) the audit log at path with mode 0600 in
// append mode. Pass key=nil for plaintext logs, or a 32-byte key for
// AES-256-GCM encryption of every record.
func Open(path string, key []byte) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // audit log path is user-configured
	if err != nil {
		return nil, fmt.Errorf("audit: open %q: %w", path, err)
	}
	l := &Logger{f: f, path: path, syncOK: true}
	if len(key) > 0 {
		if len(key) != KeySize {
			f.Close()
			return nil, ErrNoKey
		}
		gcm, err := cipher.NewGCM(aesCipher(key))
		if err != nil {
			f.Close()
			return nil, err
		}
		l.gcm = gcm
	}
	return l, nil
}

func aesCipher(key []byte) cipher.Block {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // impossible with a 32-byte key (checked by caller)
	}
	return b
}

// OpenWithPassphrase opens an encrypted log using a passphrase. On creation
// it prepends a header line {"salt":"<base64>"} so future readers can derive
// the same key.
func OpenWithPassphrase(path, passphrase string) (*Logger, error) {
	newFile := false
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		newFile = true
	}
	var salt []byte
	if newFile {
		salt = NewSalt()
		key, err := KeyFromPassphrase(passphrase, salt)
		if err != nil {
			return nil, err
		}
		l, err := Open(path, key)
		if err != nil {
			return nil, err
		}
		header, _ := json.Marshal(map[string]string{"salt": base64.StdEncoding.EncodeToString(salt)})
		l.mu.Lock()
		defer l.mu.Unlock()
		l.f.Write(append(header, '\n')) //nolint:errcheck // surfaced by subsequent writes
		return l, nil
	}
	// Existing log: read the salt from the first line.
	f, err := os.Open(path) //nolint:gosec // user-configured log
	if err != nil {
		return nil, err
	}
	var header struct {
		Salt string `json:"salt"`
	}
	if err := json.NewDecoder(f).Decode(&header); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: read salt header: %w", err)
	}
	f.Close()
	salt, err = base64.StdEncoding.DecodeString(header.Salt)
	if err != nil {
		return nil, fmt.Errorf("audit: decode salt: %w", err)
	}
	key, err := KeyFromPassphrase(passphrase, salt)
	if err != nil {
		return nil, err
	}
	return Open(path, key)
}

// Log appends one event, stamping the time if it is unset.
func (l *Logger) Log(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("audit: logger closed")
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.User == "" {
		e.User = currentUser()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: encode: %w", err)
	}
	out := line
	if l.gcm != nil {
		nonce := make([]byte, l.gcm.NonceSize())
		rand.Read(nonce) //nolint:errcheck
		sealed := l.gcm.Seal(nonce, nonce, line, nil)
		out = []byte(base64.StdEncoding.EncodeToString(sealed))
	}
	out = append(out, '\n')
	if _, err := l.f.Write(out); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	if l.syncOK {
		return l.f.Sync()
	}
	return nil
}

// Close flushes and closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.f.Close()
}

// Path returns the log file location.
func (l *Logger) Path() string { return l.path }

// ReadAll parses a log file back into events. For encrypted logs the same
// passphrase (or raw key) is required; the salt header line is skipped.
func ReadAll(path string, key []byte) ([]Event, error) {
	f, err := os.Open(path) //nolint:gosec // user-configured log
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var gcm cipher.AEAD
	if len(key) > 0 {
		if len(key) != KeySize {
			return nil, ErrNoKey
		}
		gcm, err = cipher.NewGCM(aesCipher(key))
		if err != nil {
			return nil, err
		}
	}
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var payload []byte
		if gcm != nil {
			decoded, err := base64.StdEncoding.DecodeString(string(raw))
			if err != nil || len(decoded) < gcm.NonceSize() {
				// Plaintext salt header (or corrupt line).
				var header map[string]string
				if json.Unmarshal(raw, &header) == nil {
					continue
				}
				return nil, fmt.Errorf("audit: corrupt encrypted line")
			}
			nonce, ct := decoded[:gcm.NonceSize()], decoded[gcm.NonceSize():]
			payload, err = gcm.Open(nil, nonce, ct, nil)
			if err != nil {
				return nil, fmt.Errorf("audit: decrypt: %w", err)
			}
		} else {
			if _, ok := isSaltHeader(raw); ok {
				continue
			}
			payload = raw
		}
		var e Event
		if err := json.Unmarshal(payload, &e); err != nil {
			return nil, fmt.Errorf("audit: decode: %w", err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

func isSaltHeader(raw []byte) (string, bool) {
	var h struct {
		Salt string `json:"salt"`
	}
	if err := json.Unmarshal(raw, &h); err == nil && h.Salt != "" {
		return h.Salt, true
	}
	return "", false
}

// ReadAllPassphrase decrypts a log written by OpenWithPassphrase.
func ReadAllPassphrase(path, passphrase string) ([]Event, error) {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil, err
	}
	var header struct {
		Salt string `json:"salt"`
	}
	err = json.NewDecoder(f).Decode(&header)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("audit: read salt header: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(header.Salt)
	if err != nil {
		return nil, err
	}
	key, err := KeyFromPassphrase(passphrase, salt)
	if err != nil {
		return nil, err
	}
	return ReadAll(path, key)
}

// Noop returns a logger that discards events, for tests and sandbox mode.
func Noop() *Logger {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		panic(err) // os.DevNull is always available
	}
	return &Logger{f: f}
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "unknown"
}
