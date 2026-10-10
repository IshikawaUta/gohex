// Package restapi exposes a small read-mostly REST facade over the
// service layer for scripting and remote triage. It binds to loopback
// by default, requires a bearer token on every evidence endpoint, and
// never offers a write-to-evidence route: the same read-only posture
// as the GUI.
package restapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IshikawaUta/gohex/internal/service"
)

// DefaultAddr is the loopback-only default listen address. Remote
// exposure must be an explicit, separate decision.
const DefaultAddr = "127.0.0.1:8377"

// GenerateToken returns a fresh 256-bit bearer token.
func GenerateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is fatal for auth; fall back to a
		// time-seeded value is NOT acceptable — panic loudly.
		panic("restapi: crypto/rand unavailable")
	}
	return hex.EncodeToString(b)
}

// Server is the REST facade.
type Server struct {
	app   *service.App
	token string
	mux   *http.ServeMux
}

// New builds the facade. token must be non-empty: an unauthenticated
// evidence API is never acceptable, even on loopback.
func New(app *service.App, token string) (*Server, error) {
	if token == "" {
		return nil, errors.New("restapi: refusing to start without a token")
	}
	s := &Server{app: app, token: token, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

// Handler returns the authenticated HTTP handler.
func (s *Server) Handler() http.Handler { return s.auth(s.mux) }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/version", s.wrap(s.handleVersion))
	s.mux.HandleFunc("GET /api/v1/documents", s.wrap(s.handleList))
	s.mux.HandleFunc("POST /api/v1/documents/open", s.wrap(s.handleOpen))
	s.mux.HandleFunc("GET /api/v1/documents/{id}", s.wrap(s.handleInfo))
	s.mux.HandleFunc("GET /api/v1/documents/{id}/data", s.wrap(s.handleData))
	s.mux.HandleFunc("GET /api/v1/documents/{id}/find", s.wrap(s.handleFind))
	s.mux.HandleFunc("POST /api/v1/fs/probe", s.wrap(s.handleProbe))
	s.mux.HandleFunc("GET /api/v1/fs/partitions", s.wrap(s.handlePartitions))
	s.mux.HandleFunc("GET /api/v1/fs/list", s.wrap(s.handleFsList))
	s.mux.HandleFunc("POST /api/v1/fs/export", s.wrap(s.handleFsExport))
}

// auth enforces "Authorization: Bearer <token>" with a constant-time
// comparison. /api/v1/health stays open so liveness probes do not
// need the secret; it reveals nothing about evidence.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}
		h := r.Header.Get("Authorization")
		const p = "Bearer "
		if !strings.HasPrefix(h, p) {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		got := h[len(p):]
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeErr(w, http.StatusUnauthorized, "bad token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) wrap(h func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) error {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.app.Version()})
	return nil
}

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request) error {
	writeJSON(w, http.StatusOK, s.app.ListDocuments())
	return nil
}

type openReq struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
	Range  bool   `json:"range"`
}

func (s *Server) handleOpen(w http.ResponseWriter, r *http.Request) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("restapi: open: %v", r)
		}
	}()
	var req openReq
	if jerr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); jerr != nil {
		return fmt.Errorf("bad json: %w", jerr)
	}
	if req.Path == "" {
		return errors.New("path required")
	}
	var doc service.DocInfo
	if req.Range {
		doc, err = s.app.OpenRange(req.Path, req.Offset, req.Size)
	} else {
		doc, err = s.app.OpenFile(req.Path)
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, doc)
	return nil
}

func parseID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) error {
	id, perr := parseID(r)
	if perr != nil {
		return perr
	}
	doc, err := s.app.DocumentInfo(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return nil
	}
	writeJSON(w, http.StatusOK, doc)
	return nil
}

func (s *Server) handleData(w http.ResponseWriter, r *http.Request) error {
	id, perr := parseID(r)
	if perr != nil {
		return perr
	}
	q := r.URL.Query()
	off, _ := strconv.ParseInt(q.Get("offset"), 10, 64)
	length, _ := strconv.ParseInt(q.Get("length"), 10, 64)
	if length <= 0 || length > 4<<20 {
		length = 4 << 20 // one request may not pull more than 4 MiB
	}
	win, err := s.app.ReadWindow(id, off, length)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return nil
	}
	writeJSON(w, http.StatusOK, win)
	return nil
}

func (s *Server) handleFind(w http.ResponseWriter, r *http.Request) error {
	id, perr := parseID(r)
	if perr != nil {
		return perr
	}
	q := r.URL.Query()
	doc, err := s.app.DocumentInfo(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return nil
	}
	from, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	max, _ := strconv.Atoi(q.Get("max"))
	if max <= 0 || max > 500 {
		max = 100
	}
	mode := q.Get("mode")
	if mode == "" {
		mode = "text"
	}
	res, ferr := s.app.Find(service.FindRequest{
		ID:       id,
		Mode:     mode,
		Pattern:  q.Get("pattern"),
		Encoding: doc.Encoding,
		CaseFold: q.Get("caseFold") != "false",
		From:     from,
		Wrap:     true,
		Max:      max,
	})
	if ferr != nil {
		writeErr(w, http.StatusBadRequest, ferr.Error())
		return nil
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) error {
	var req openReq
	if jerr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); jerr != nil {
		return fmt.Errorf("bad json: %w", jerr)
	}
	info, err := s.app.ProbeFileSystem(req.Path, req.Offset, req.Size)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return nil
	}
	writeJSON(w, http.StatusOK, info)
	return nil
}

func (s *Server) handlePartitions(w http.ResponseWriter, r *http.Request) error {
	p := r.URL.Query().Get("path")
	if p == "" {
		return errors.New("path required")
	}
	layout, err := s.app.Partitions(p)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return nil
	}
	writeJSON(w, http.StatusOK, layout)
	return nil
}

func (s *Server) handleFsList(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	if q.Get("path") == "" {
		return errors.New("path required")
	}
	off, _ := strconv.ParseInt(q.Get("offset"), 10, 64)
	size, _ := strconv.ParseInt(q.Get("size"), 10, 64)
	entries, err := s.app.FsList(q.Get("path"), off, size, q.Get("dir"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return nil
	}
	writeJSON(w, http.StatusOK, entries)
	return nil
}

func (s *Server) handleFsExport(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Path   string `json:"path"`
		Offset int64  `json:"offset"`
		Size   int64  `json:"size"`
		FsPath string `json:"fsPath"`
		Dst    string `json:"dst"`
	}
	if jerr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); jerr != nil {
		return fmt.Errorf("bad json: %w", jerr)
	}
	if req.Path == "" || req.FsPath == "" || req.Dst == "" {
		return errors.New("path, fsPath and dst required")
	}
	res, err := s.app.FsExport(req.Path, req.Offset, req.Size, req.FsPath, req.Dst)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return nil
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// ListenAndServe serves until ctx cancellation. Only loopback binds
// are accepted: exposing evidence over the network is a deployment
// decision that belongs behind a VPN or SSH tunnel, not a flag.
func ListenAndServe(app *service.App, addr, token string) error {
	host, _, herr := net.SplitHostPort(addr)
	if herr != nil {
		return fmt.Errorf("restapi: bad address %q: %w", addr, herr)
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return fmt.Errorf("restapi: refusing non-loopback bind %q (use an SSH tunnel)", host)
	}
	srv, err := New(app, token)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	return httpSrv.ListenAndServe()
}
