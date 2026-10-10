// Command gohex-server exposes a read-mostly REST API over GoHex's
// forensic service for scripting and remote triage.
//
// It is OFF by default (nothing starts it), binds loopback-only, and
// refuses to run without a bearer token. Evidence writes are not
// routable at all — exports go through the same audited service paths
// the GUI uses.
//
// Usage:
//
//	gohex-server -token "$(openssl rand -hex 32)"
//	curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8377/api/v1/version
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/IshikawaUta/gohex/internal/restapi"
	"github.com/IshikawaUta/gohex/internal/service"
)

func main() {
	addr := flag.String("listen", restapi.DefaultAddr, "loopback listen address (127.0.0.1 only)")
	token := flag.String("token", os.Getenv("GOHEX_SERVER_TOKEN"), "bearer token (or GOHEX_SERVER_TOKEN); generated once when empty")
	version := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	app, err := service.New("", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gohex-server:", err)
		os.Exit(1)
	}
	defer app.Close()

	if *version {
		fmt.Println(app.Version())
		return
	}

	tok := *token
	generated := false
	if tok == "" {
		tok = restapi.GenerateToken()
		generated = true
	}
	if generated {
		fmt.Fprintln(os.Stderr, "gohex-server: generated token (store it now, it will not be shown again):")
		fmt.Fprintln(os.Stderr, "  "+tok)
	}

	fmt.Fprintf(os.Stderr, "gohex-server: listening on http://%s (loopback only, token required)\n", *addr)
	if err := restapi.ListenAndServe(app, *addr, tok); err != nil {
		fmt.Fprintln(os.Stderr, "gohex-server:", err)
		os.Exit(1)
	}
}
