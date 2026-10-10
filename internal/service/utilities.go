package service

import (
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"strings"

	"github.com/IshikawaUta/gohex/internal/audit"
	"github.com/IshikawaUta/gohex/internal/util"
)

// --- Entropy & frequency (operates on a path, streamed) ---

// EntropyOf returns the Shannon entropy in bits/byte of the whole file
// at path, plus its size.
func (a *App) EntropyOf(path string) (map[string]float64, error) {
	f, err := os.Open(absPath(path))
	if err != nil {
		return nil, fmt.Errorf("service: entropy: %w", err)
	}
	defer f.Close()
	h, n, err := util.EntropyReader(f)
	if err != nil {
		return nil, fmt.Errorf("service: entropy: %w", err)
	}
	return map[string]float64{"entropy": h, "bytes": float64(n)}, nil
}

// ByteFreq returns the top-n byte histogram of the file at path.
func (a *App) ByteFreq(path string, topN int) ([]util.ByteCount, error) {
	if topN <= 0 || topN > 256 {
		topN = 256
	}
	body, err := util.HeadBytes(absPath(path), 64<<20) // cap at 64 MiB
	if err != nil {
		return nil, fmt.Errorf("service: byte frequency: %w", err)
	}
	all := util.ByteFrequency(body)
	if len(all) > topN {
		all = all[:topN]
	}
	return all, nil
}

// --- Hex calculator ---

// HexCalc evaluates an integer expression. Accepts decimal, 0x-hex,
// + - * / % and parentheses. The result is returned both ways so the
// GUI can render decimal and hex without re-parsing.
func (a *App) HexCalc(expr string) (map[string]string, error) {
	v, err := util.EvalExpr(expr)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"expr":   expr,
		"dec":    fmt.Sprintf("%d", v),
		"hex":    fmt.Sprintf("0x%X", uint64(v)),
		"hexlow": fmt.Sprintf("%x", uint64(v)),
		"oct":    fmt.Sprintf("0o%o", uint64(v)),
		"bin":    fmt.Sprintf("0b%b", uint64(v)),
		"bytes":  fmt.Sprintf("%d", byteLen(v)),
	}, nil
}

func byteLen(v int64) int {
	switch {
	case v == 0 || v == -1:
		return 1
	case v >= -0x80 && v <= 0x7F:
		return 1
	case v >= -0x8000 && v <= 0x7FFF:
		return 2
	case v >= -1<<31 && v <= 1<<31-1:
		return 4
	default:
		return 8
	}
}

// --- Regex tester / strings (on a path) ---

// RegexTest runs a regex over the file at path (capped at 64 MiB)
// and returns up to limit matches.
func (a *App) RegexTest(path, pattern string, limit int) ([]util.SearchMatch, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, errors.New("service: regex: empty pattern")
	}
	body, err := util.HeadBytes(absPath(path), 64<<20)
	if err != nil {
		return nil, fmt.Errorf("service: regex: %w", err)
	}
	return util.RegexSearch(body, pattern, limit)
}

// StringsOf extracts printable strings from the file at path.
func (a *App) StringsOf(path string, minLen, limit int) ([]util.SearchMatch, error) {
	body, err := util.HeadBytes(absPath(path), 64<<20)
	if err != nil {
		return nil, fmt.Errorf("service: strings: %w", err)
	}
	return util.ExtractStrings(body, minLen, limit), nil
}

// --- Split / join ---

// SplitFile splits src into pieces of pieceSize bytes named by
// dstPattern (must contain %d) and returns the piece paths.
func (a *App) SplitFile(src, dstPattern string, pieceSize int64) ([]string, error) {
	paths, err := util.SplitFile(absPath(src), absPath(dstPattern), pieceSize)
	if err != nil {
		return nil, fmt.Errorf("service: split: %w", err)
	}
	a.auditOp(audit.ActionExport, "split", absPath(src), map[string]string{
		"pieces": fmt.Sprintf("%d", len(paths)),
		"size":   fmt.Sprintf("%d", pieceSize),
	})
	return paths, nil
}

// JoinFiles concatenates parts into dst.
func (a *App) JoinFiles(parts []string, dst string) (int64, error) {
	for i := range parts {
		parts[i] = absPath(parts[i])
	}
	n, err := util.JoinFiles(parts, absPath(dst))
	if err != nil {
		return 0, fmt.Errorf("service: join: %w", err)
	}
	a.auditOp(audit.ActionImport, "join", absPath(dst), map[string]string{"parts": fmt.Sprintf("%d", len(parts))})
	return n, nil
}

// --- Secure delete ---

// Shred overwrites and removes path. bestEffort is always true in
// practice (CoW/SSD), and the GUI must surface that caveat; the audit
// record carries it so the examiner's notes reflect reality.
func (a *App) Shred(path string, passes int) error {
	abs := absPath(path)
	if err := util.Shred(abs, passes); err != nil {
		return fmt.Errorf("service: shred: %w", err)
	}
	a.auditOp(audit.ActionExport, "shred", abs, map[string]string{
		"passes":     fmt.Sprintf("%d", passes),
		"bestEffort": "true",
	})
	return nil
}

// --- Generators ---

// PasswordGen returns a random password of the given length.
func (a *App) PasswordGen(n int) (string, error) {
	return util.Password(n)
}

// UUIDGen returns a fresh RFC 4122 v4 UUID.
func (a *App) UUIDGen() (string, error) {
	return util.UUIDv4()
}

// ULIDGen returns a fresh lexicographically-sortable ULID.
func (a *App) ULIDGen() (string, error) {
	return util.ULID()
}

// RandomHex returns n random bytes as uppercase hex.
func (a *App) RandomHex(n int) (string, error) {
	return util.RandomBytes(n)
}

// --- Timestamp converter ---

// TimestampConvert renders an epoch value in every format a forensic
// examiner needs. unit is s / ms / us / ns (default s).
func (a *App) TimestampConvert(epoch int64, unit string) (map[string]string, error) {
	return util.ConvertTimestamp(epoch, unit)
}

// --- PNG export of the hex view ---

// ExportPNG writes a grayscale PNG rendering of [offset, offset+length)
// of the document with the given id. Each input byte becomes a
// scale×scale block, the classic "screenshot the bytes" export. It is
// read-only and audited as an export.
func (a *App) ExportPNG(id int64, offset, length int64, scale int, path string) (SaveResult, error) {
	d, err := a.lookup(id)
	if err != nil {
		return SaveResult{}, err
	}
	if length <= 0 || length > 1<<24 {
		return SaveResult{}, errors.New("service: export png: length must be in 1..16777216")
	}
	if scale < 1 || scale > 16 {
		scale = 4
	}
	if offset < 0 {
		return SaveResult{}, errors.New("service: export png: negative offset")
	}
	buf := make([]byte, length)
	if _, err := d.document.ReadAt(buf, offset); err != nil {
		return SaveResult{}, fmt.Errorf("service: export png: %w", err)
	}
	abs := absPath(path)
	if err := writeGrayPNG(abs, buf, int(length), scale); err != nil {
		return SaveResult{}, err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return SaveResult{}, err
	}
	a.auditOp(audit.ActionExport, "png", abs, map[string]string{
		"doc":    fmt.Sprintf("%d", id),
		"bytes":  fmt.Sprintf("%d", length),
		"offset": fmt.Sprintf("%d", offset),
	})
	return SaveResult{Path: abs, BytesSaved: fi.Size(), Mode: "png"}, nil
}

// writeGrayPNG renders data as a width×height grayscale image, each
// byte a pixel, scaled by an integer factor.
func writeGrayPNG(path string, data []byte, width, scale int) error {
	if width <= 0 {
		return errors.New("service: export png: empty data")
	}
	height := (len(data) + width - 1) / width
	img := image.NewGray(image.Rect(0, 0, width*scale, height*scale))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			i := y*width + x
			var v byte
			if i < len(data) {
				v = data[i]
			}
			g := color.Gray{Y: v}
			for dy := 0; dy < scale; dy++ {
				for dx := 0; dx < scale; dx++ {
					img.SetGray(x*scale+dx, y*scale+dy, g)
				}
			}
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("service: export png: %w", err)
	}
	defer f.Close()
	return png.Encode(f, img)
}

func (a *App) auditOp(action audit.Action, op, target string, detail map[string]string) {
	_ = a.log.Log(audit.Event{
		Action: action,
		Target: target,
		Result: audit.ResultOK,
		Detail: detail,
	})
}
