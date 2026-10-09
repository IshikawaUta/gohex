// Command gohex-cli is the read-only command-line companion to the GoHex
// GUI: it hashes files, reports container format / size / partition tables
// and searches for byte or text patterns. It never writes to the inspected
// file and takes no editing verbs — write paths live in the GUI only.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/IshikawaUta/gohex/internal/disk"
	bincoding "github.com/IshikawaUta/gohex/internal/encoding"
	"github.com/IshikawaUta/gohex/internal/hash"
	"github.com/IshikawaUta/gohex/internal/hex"
	"github.com/IshikawaUta/gohex/internal/image"
	"github.com/IshikawaUta/gohex/pkg/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "hash":
		return cmdHash(args[1:], stdout, stderr)
	case "info":
		return cmdInfo(args[1:], stdout, stderr)
	case "search":
		return cmdSearch(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "gohex-cli %s\n", version.Version)
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "gohex-cli: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `gohex-cli — read-only hex/forensics companion CLI

Usage:
  gohex-cli hash   [-algo sha256] FILE     hash a file (streams; works on E01/L01/VHD/...)
  gohex-cli info   FILE                    size, container format, partition table
  gohex-cli search [-hex PATTERN | -text PATTERN] [-enc ascii|utf16le|utf16be] [-limit N] FILE
  gohex-cli version

Patterns:
  -hex  "DE AD ?? EF"   hex bytes, ?? is a wildcard nibble pair
  -text "password"      literal text in the encoding given by -enc (default ascii)

Exit codes: 0 ok, 1 error, 2 usage, 3 no matches.
`)
}

func cmdHash(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hash", flag.ContinueOnError)
	fs.SetOutput(stderr)
	algoName := fs.String("algo", "sha256", "hash algorithm (md5, sha1, sha256, sha512, blake2b-256, crc32, ...)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "gohex-cli hash: exactly one FILE required")
		return 2
	}
	algo, err := hash.Parse(*algoName)
	if err != nil {
		fmt.Fprintf(stderr, "gohex-cli hash: %v\n", err)
		return 1
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "gohex-cli hash: %v\n", err)
		return 1
	}
	defer f.Close()
	sum, err := hash.Reader(algo, f, nil)
	if err != nil {
		fmt.Fprintf(stderr, "gohex-cli hash: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, hash.Format(algo, sum, false))
	return 0
}

func cmdInfo(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "gohex-cli info: exactly one FILE required")
		return 2
	}
	r, err := image.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "gohex-cli info: %v\n", err)
		return 1
	}
	defer r.Close()
	fmt.Fprintf(stdout, "file\t%s\n", fs.Arg(0))
	fmt.Fprintf(stdout, "size\t%d\n", r.Size())
	fmt.Fprintf(stdout, "format\t%s\n", r.Format())
	t, err := disk.Parse(r)
	if err != nil {
		// No/foreign partition table is not an error for a forensic image.
		fmt.Fprintln(stdout, "partitions\t(none detected)")
		return 0
	}
	fmt.Fprintf(stdout, "scheme\t%s\n", t.Kind)
	for _, p := range t.Partitions {
		fmt.Fprintf(stdout, "partition\t%d\t%s\tstart=%d\tsize=%d\n",
			p.Index, p.Name, p.Start, p.Size)
	}
	for _, w := range t.Warnings {
		fmt.Fprintf(stdout, "warning\t%s\n", w)
	}
	return 0
}

func cmdSearch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hexPat := fs.String("hex", "", "hex byte pattern (?? = wildcard pair)")
	textPat := fs.String("text", "", "literal text pattern")
	encName := fs.String("enc", "ascii", "text encoding: ascii, utf16le or utf16be")
	limit := fs.Int("limit", 100, "maximum number of matches to report")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "gohex-cli search: exactly one FILE required")
		return 2
	}
	if (*hexPat == "") == (*textPat == "") {
		fmt.Fprintln(stderr, "gohex-cli search: exactly one of -hex or -text is required")
		return 2
	}
	var p *hex.Pattern
	var err error
	if *hexPat != "" {
		p, err = hex.ParseHexPattern(*hexPat)
	} else {
		var enc bincoding.Encoding
		switch *encName {
		case "ascii":
			enc = bincoding.ASCII
		case "utf16le":
			enc = bincoding.UTF16LE
		case "utf16be":
			enc = bincoding.UTF16BE
		default:
			fmt.Fprintf(stderr, "gohex-cli search: unknown -enc %q\n", *encName)
			return 2
		}
		p, err = hex.NewTextPattern(*textPat, enc, false)
	}
	if err != nil {
		fmt.Fprintf(stderr, "gohex-cli search: %v\n", err)
		return 1
	}
	r, err := image.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "gohex-cli search: %v\n", err)
		return 1
	}
	defer r.Close()
	matches, err := hex.FindAll(r, p, 0, r.Size(), *limit)
	if err != nil {
		fmt.Fprintf(stderr, "gohex-cli search: %v\n", err)
		return 1
	}
	if len(matches) == 0 {
		return 3
	}
	for _, m := range matches {
		fmt.Fprintf(stdout, "0x%016x\t%d\n", m.Start, m.Length)
	}
	return 0
}
