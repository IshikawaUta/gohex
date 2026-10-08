package sqlite

import (
	"fmt"
	"strings"
)

// This file recovers column names from the CREATE TABLE text stored in
// sqlite_master. It is not a SQL parser: it reads enough of the grammar to
// name the columns of a table, and it refuses anything it does not
// understand instead of guessing, because a wrong column name silently maps
// every row to the wrong field.
//
// Only what the record format cannot tell us is parsed here. Types, NOT
// NULL and PRIMARY KEY matter to callers; defaults and CHECK bodies are
// skipped wholesale.

type tokKind uint8

const (
	tokIdent tokKind = iota
	tokString
	tokNumber
	tokPunct
)

type token struct {
	kind   tokKind
	text   string // unquoted value for idents and strings, raw text otherwise
	depth  int    // parenthesis nesting before the token
	quoted bool   // written quoted in the source, so never a keyword
}

var constraintKeywords = map[string]bool{
	"constraint":    true,
	"primary":       true,
	"unique":        true,
	"check":         true,
	"foreign":       true,
	"not":           true,
	"null":          true,
	"default":       true,
	"collate":       true,
	"references":    true,
	"generated":     true,
	"autoincrement": true,
}

// tokenizeDDL splits a CREATE TABLE statement, unquoting identifiers and
// recording parenthesis depth for every token.
func tokenizeDDL(s string) ([]token, error) {
	var out []token
	depth := 0
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				i = len(s)
			} else {
				i += 2 + end + 2
			}
		case c == '\'':
			v, n, err := readQuoted(s[i:], '\'', true)
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: tokString, text: v, depth: depth})
			i += n
		case c == '"' || c == '`':
			v, n, err := readQuoted(s[i:], c, true)
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: tokIdent, text: v, depth: depth, quoted: true})
			i += n
		case c == '[':
			end := strings.IndexByte(s[i:], ']')
			if end < 0 {
				return nil, fmt.Errorf("unterminated [identifier")
			}
			out = append(out, token{kind: tokIdent, text: s[i+1 : i+end], depth: depth, quoted: true})
			i += end + 1
		case c == '(':
			out = append(out, token{kind: tokPunct, text: "(", depth: depth})
			depth++
			i++
		case c == ')':
			if depth > 0 {
				depth--
			}
			out = append(out, token{kind: tokPunct, text: ")", depth: depth})
			i++
		case isWordStart(c):
			j := i
			for j < len(s) && isWordChar(s[j]) {
				j++
			}
			out = append(out, token{kind: tokIdent, text: s[i:j], depth: depth})
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && (isDigit(s[j]) || s[j] == '.' || s[j] == 'x' || s[j] == 'X' ||
				isHexDigit(s[j]) || s[j] == '+' || s[j] == '-') {
				j++
			}
			out = append(out, token{kind: tokNumber, text: s[i:j], depth: depth})
			i = j
		default:
			out = append(out, token{kind: tokPunct, text: string(c), depth: depth})
			i++
		}
	}
	return out, nil
}

func isDigit(c byte) bool    { return c >= '0' && c <= '9' }
func isHexDigit(c byte) bool { return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') }
func isWordStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}
func isWordChar(c byte) bool { return isWordStart(c) || isDigit(c) || c == '$' }

// readQuoted reads a delimited run starting at s[0], un-doubling the escape
// used by SQL (” inside '...', "" inside "..." and `...`).
func readQuoted(s string, delim byte, doubled bool) (string, int, error) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		if s[i] != delim {
			b.WriteByte(s[i])
			continue
		}
		if doubled && i+1 < len(s) && s[i+1] == delim {
			b.WriteByte(delim)
			i++
			continue
		}
		return b.String(), i + 1, nil
	}
	return "", 0, fmt.Errorf("unterminated %c...%c literal", delim, delim)
}

// parseCreateTable extracts the column list from a CREATE TABLE statement.
// The third result reports WITHOUT ROWID, which changes the on-disk
// representation from a table b-tree to an index b-tree.
func parseCreateTable(sql string) (string, []Column, bool, error) {
	toks, err := tokenizeDDL(sql)
	if err != nil {
		return "", nil, false, err
	}
	kw := func(t token) string {
		if t.kind == tokIdent {
			return strings.ToLower(t.text)
		}
		return t.text
	}
	if len(toks) == 0 {
		return "", nil, false, fmt.Errorf("empty statement")
	}
	at := func(i int) (token, error) {
		if i >= len(toks) {
			return token{}, fmt.Errorf("statement ends unexpectedly")
		}
		return toks[i], nil
	}
	i := 0
	first, err := at(0)
	if err != nil || kw(first) != "create" {
		return "", nil, false, fmt.Errorf("statement does not start with CREATE")
	}
	i++
	for {
		t, err := at(i)
		if err != nil {
			return "", nil, false, fmt.Errorf("statement ends after CREATE")
		}
		if kw(t) == "temp" || kw(t) == "temporary" {
			i++
			continue
		}
		if kw(t) == "virtual" {
			return "", nil, false, fmt.Errorf("virtual tables have no stored column list")
		}
		if kw(t) != "table" {
			return "", nil, false, fmt.Errorf("expected TABLE, found %q", t.text)
		}
		i++
		break
	}
	if t, err := at(i); err == nil && kw(t) == "if" { // IF NOT EXISTS
		i += 3
	}
	if i >= len(toks) {
		return "", nil, false, fmt.Errorf("statement ends before the table name")
	}
	name := toks[i].text
	i++
	if i < len(toks) && toks[i].text == "." { // schema-qualified name
		i++
		if i < len(toks) {
			name = toks[i].text
			i++
		}
	}
	if i >= len(toks) || toks[i].text != "(" {
		return name, nil, false, fmt.Errorf("expected a column list after table %q", name)
	}
	body := toks[i+1:]
	// Cut at the matching close paren.
	end := -1
	for j, t := range body {
		if t.text == ")" && t.depth == 0 {
			end = j
			break
		}
	}
	if end < 0 {
		return name, nil, false, fmt.Errorf("unbalanced parentheses in the column list of %q", name)
	}
	withoutRowid := false
	for _, t := range toks[i+1+end+1:] {
		if t.kind == tokIdent && strings.EqualFold(t.text, "without") {
			withoutRowid = true
		}
	}

	elements := splitElements(body[:end])
	// Table-level constraints come after the columns they refer to, so the
	// PRIMARY KEY list has to be collected before the columns are read.
	tablePK := map[string]bool{}
	for _, elem := range elements {
		if len(elem) == 0 || elem[0].quoted || elem[0].depth != 1 {
			continue
		}
		if strings.EqualFold(elem[0].text, "primary") && constraintKeywords[strings.ToLower(elem[0].text)] {
			for _, c := range primaryKeys(elem) {
				tablePK[strings.ToLower(c)] = true
			}
		}
	}

	var cols []Column
	for _, elem := range elements {
		if len(elem) == 0 {
			continue
		}
		if !elem[0].quoted && elem[0].depth == 1 && constraintKeywords[strings.ToLower(elem[0].text)] {
			continue // table-level constraint, not a column
		}
		if elem[0].kind != tokIdent {
			return name, nil, withoutRowid, fmt.Errorf("malformed column definition starting with %q", elem[0].text)
		}
		col := Column{Name: elem[0].text}
		inType := true
		for i := 1; i < len(elem); i++ {
			t := elem[i]
			if inType {
				// Everything up to the first constraint is the declared type,
				// including the contents of VARCHAR(255) or DECIMAL(10, 2).
				if t.depth == 1 && startsConstraint(elem, i) {
					inType = false
				} else {
					col.Type = appendType(col.Type, t.text)
					continue
				}
			} else if t.depth != 1 {
				continue // inside CHECK(...), DEFAULT (…), a nested list
			}
			if !t.quoted && strings.EqualFold(t.text, "not") {
				col.NotNull = true // NOT NULL is the only constraint read back
			}
			if !t.quoted && strings.EqualFold(t.text, "primary") {
				col.PK, col.selfPK = true, true
			}
		}
		if tablePK[strings.ToLower(col.Name)] {
			col.PK = true
		}
		cols = append(cols, col)
	}
	if len(cols) == 0 {
		return name, nil, withoutRowid, fmt.Errorf("no columns found in %q", name)
	}
	return name, cols, withoutRowid, nil
}

// startsConstraint reports whether elem[i] opens a column constraint. A
// quoted token is always an identifier, never a keyword, so a column named
// "check" is not mistaken for a CHECK constraint. "AS" only starts a
// generated-column constraint when ALWAYS or a parenthesised expression
// follows.
func startsConstraint(elem []token, i int) bool {
	t := elem[i]
	if t.quoted || t.kind != tokIdent {
		return false
	}
	if !strings.EqualFold(t.text, "as") {
		return constraintKeywords[strings.ToLower(t.text)]
	}
	if i+1 >= len(elem) {
		return false
	}
	nxt := elem[i+1]
	return nxt.text == "(" || (nxt.kind == tokIdent && !nxt.quoted && strings.EqualFold(nxt.text, "always"))
}

// appendType joins declared-type tokens the way they were written: no space
// around parentheses, commas or dots, a space everywhere else, so
// DECIMAL(10, 2) and UNSIGNED BIG INT round-trip unchanged.
func appendType(cur, add string) string {
	if cur == "" {
		return add
	}
	switch add {
	case "(", ")", ",", ".":
		return cur + add
	}
	if strings.HasSuffix(cur, "(") || strings.HasSuffix(cur, ".") {
		return cur + add
	}
	return cur + " " + add
}

// splitElements splits a column list on the commas that separate its
// top-level items, keeping nested parentheses attached to their item.
func splitElements(toks []token) [][]token {
	var out [][]token
	var cur []token
	for _, t := range toks {
		if t.text == "," && t.depth == 1 {
			out = append(out, cur)
			cur = nil
			continue
		}
		cur = append(cur, t)
	}
	return append(out, cur)
}

// primaryKeys returns the column names inside a table-level
// PRIMARY KEY (a, b) clause.
func primaryKeys(elem []token) []string {
	var out []string
	expect := false // true right after "(" or "," inside the key list
	for _, t := range elem {
		if t.depth == 1 && t.text == "(" {
			expect = true
			continue
		}
		if t.depth == 1 && t.text == ")" {
			expect = false
			continue
		}
		if t.depth == 2 && t.text == "," && t.kind == tokPunct {
			expect = true
			continue
		}
		if expect && t.depth == 2 && t.kind == tokIdent {
			out = append(out, t.text)
			expect = false
		}
	}
	return out
}
