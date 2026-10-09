// Package script runs examiner automation scripts (Starlark) with
// read-only access to open documents.
//
// Scripts are sandboxed and deterministic by construction: the Starlark
// environment has no filesystem, network, clock or randomness, module
// loading is disabled, and the only capability a script receives is the
// injected "gohex" module for listing, reading and searching the documents
// the examiner already opened. Execution is bounded by a wall-clock
// timeout and an interpreter step limit, and print() output is captured
// for the caller instead of touching any real stdout.
package script

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/IshikawaUta/gohex/pkg/version"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

// Limits for one script run.
const (
	DefaultTimeout = 30 * time.Second
	MaxSteps       = 1_000_000
	MaxOutput      = 1 << 20 // captured print() output cap
	MaxReadSize    = 16 << 20
	MaxFindResults = 500
	MaxPatternLen  = 4096
)

// Doc describes one open document visible to scripts.
type Doc struct {
	ID   int64
	Name string
	Size int64
}

// Host is the document access surface the service injects into scripts.
// It is called only from the script's own goroutine.
type Host interface {
	// Docs lists the open documents.
	Docs() []Doc
	// Read returns up to size bytes of document id at offset; a read past
	// the end returns the bytes that exist.
	Read(id, offset, size int64) ([]byte, error)
	// Find returns up to limit match offsets of the ASCII text pattern in
	// document id, scanning forward from offset.
	Find(id int64, text string, offset int64, limit int) ([]int64, error)
}

// Result carries the outcome of a run. Output holds everything print()
// wrote, even when the run failed.
type Result struct {
	Output string
	Steps  uint64
}

// Run executes the Starlark program in src under the name name. A non-nil
// error means the script failed (syntax error, runtime error, limit
// exceeded); the caller still gets the captured output in Result.
func Run(ctx context.Context, host Host, name string, src []byte) (Result, error) {
	if host == nil {
		return Result{}, errors.New("script: nil host")
	}
	var out strings.Builder
	thread := &starlark.Thread{
		Name: name,
		Print: func(_ *starlark.Thread, msg string) {
			if out.Len() < MaxOutput {
				out.WriteString(msg)
				out.WriteByte('\n')
			}
		},
		Load: func(_ *starlark.Thread, module string) (starlark.StringDict, error) {
			return nil, fmt.Errorf("loading module %q is disabled", module)
		},
	}
	thread.SetMaxExecutionSteps(MaxSteps)

	gohex := &starlarkstruct.Module{
		Name: "gohex",
		Members: starlark.StringDict{
			"docs":    starlark.NewBuiltin("docs", sDocs(host)),
			"read":    starlark.NewBuiltin("read", sRead(host)),
			"find":    starlark.NewBuiltin("find", sFind(host)),
			"hash":    starlark.NewBuiltin("hash", sHash),
			"version": starlark.NewBuiltin("version", sVersion),
		},
	}

	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()
	done := make(chan error, 1)
	// Scripts get the full statement set (top-level for/if, while loops)
	// but not recursion or global reassignment; the step limit and the
	// timeout are the real backstops.
	opts := &syntax.FileOptions{While: true, TopLevelControl: true}
	go func() {
		_, err := starlark.ExecFileOptions(opts, thread, name, string(src),
			starlark.StringDict{"gohex": gohex})
		done <- err
	}()
	var runErr error
	select {
	case runErr = <-done:
	case <-ctx.Done():
		thread.Cancel("script timed out")
		runErr = <-done
		if runErr == nil {
			runErr = errors.New("script timed out")
		}
	}
	res := Result{Output: out.String(), Steps: thread.Steps}
	if runErr != nil {
		var evalErr *starlark.EvalError
		if errors.As(runErr, &evalErr) {
			runErr = fmt.Errorf("script: %s", evalErr.Backtrace())
		} else {
			runErr = fmt.Errorf("script: %w", runErr)
		}
		return res, runErr
	}
	return res, nil
}

// --- gohex module builtins -------------------------------------------------

func sDocs(host Host) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackPositionalArgs(b.Name(), args, nil, 0); err != nil {
			return nil, err
		}
		docs := host.Docs()
		list := make([]starlark.Value, 0, len(docs))
		for _, d := range docs {
			list = append(list, starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
				"id":   starlark.MakeInt64(d.ID),
				"name": starlark.String(d.Name),
				"size": starlark.MakeInt64(d.Size),
			}))
		}
		return starlark.NewList(list), nil
	}
}

func sRead(host Host) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		var id, offset, size int
		if err := starlark.UnpackPositionalArgs(b.Name(), args, nil, 3, &id, &offset, &size); err != nil {
			return nil, err
		}
		if offset < 0 || size < 0 {
			return nil, fmt.Errorf("gohex.read: offset and size must be >= 0")
		}
		if size > MaxReadSize {
			return nil, fmt.Errorf("gohex.read: size %d exceeds the %d-byte cap", size, MaxReadSize)
		}
		data, err := host.Read(int64(id), int64(offset), int64(size))
		if err != nil {
			return nil, fmt.Errorf("gohex.read: %w", err)
		}
		return starlark.Bytes(data), nil
	}
}

func sFind(host Host) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var id int
		var text string
		offset := 0
		limit := 100
		if err := starlark.UnpackArgs(b.Name(), args, kwargs,
			"id", &id, "text", &text, "offset?", &offset, "limit?", &limit); err != nil {
			return nil, err
		}
		if text == "" {
			return nil, errors.New("gohex.find: empty text pattern")
		}
		if len(text) > MaxPatternLen {
			return nil, fmt.Errorf("gohex.find: pattern longer than %d bytes", MaxPatternLen)
		}
		if offset < 0 {
			return nil, errors.New("gohex.find: offset must be >= 0")
		}
		if limit <= 0 || limit > MaxFindResults {
			limit = MaxFindResults
		}
		offsets, err := host.Find(int64(id), text, int64(offset), limit)
		if err != nil {
			return nil, fmt.Errorf("gohex.find: %w", err)
		}
		list := make([]starlark.Value, 0, len(offsets))
		for _, off := range offsets {
			list = append(list, starlark.MakeInt64(off))
		}
		return starlark.NewList(list), nil
	}
}

func sHash(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Bytes
	algo := "sha256"
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "data", &data, "algo?", &algo); err != nil {
		return nil, err
	}
	sum, err := hashSum(algo, []byte(data))
	if err != nil {
		return nil, fmt.Errorf("gohex.hash: %w", err)
	}
	return starlark.String(sum), nil
}

func sVersion(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(b.Name(), args, nil, 0); err != nil {
		return nil, err
	}
	return starlark.String(version.Product + " " + version.Version), nil
}
