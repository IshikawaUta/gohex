package sqlite

import (
	"strings"
	"testing"
)

// The DDL reader decides which column every value belongs to, so a wrong
// answer here shows up as silently mislabelled evidence. These cases are the
// shapes that actually appear in browser databases plus the ones most likely
// to be mis-parsed.
func TestParseCreateTable(t *testing.T) {
	cases := []struct {
		name     string
		sql      string
		wantName string
		wantCols []Column
		wantWout bool
		wantErr  string
	}{
		{
			name:     "plain",
			sql:      `CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT NOT NULL)`,
			wantName: "t",
			wantCols: []Column{{Name: "a", Type: "INTEGER", PK: true, selfPK: true}, {Name: "b", Type: "TEXT", NotNull: true}},
		},
		{
			name:     "table level primary key does not alias the rowid",
			sql:      `CREATE TABLE t(a INTEGER, b TEXT, PRIMARY KEY(a, b))`,
			wantName: "t",
			wantCols: []Column{{Name: "a", Type: "INTEGER", PK: true}, {Name: "b", Type: "TEXT", PK: true}},
		},
		{
			name:     "quoted columns that look like keywords",
			sql:      `CREATE TABLE t("check" INTEGER, "primary" TEXT, [foreign] BLOB)`,
			wantName: "t",
			wantCols: []Column{{Name: "check", Type: "INTEGER"}, {Name: "primary", Type: "TEXT"}, {Name: "foreign", Type: "BLOB"}},
		},
		{
			name:     "types with parentheses and commas",
			sql:      `CREATE TABLE t(a VARCHAR(255) NOT NULL, b DECIMAL(10, 2) DEFAULT 0, c UNSIGNED BIG INT)`,
			wantName: "t",
			wantCols: []Column{
				{Name: "a", Type: "VARCHAR(255)", NotNull: true},
				{Name: "b", Type: "DECIMAL(10, 2)"},
				{Name: "c", Type: "UNSIGNED BIG INT"},
			},
		},
		{
			name:     "check constraint body is skipped",
			sql:      `CREATE TABLE t(c INTEGER CHECK (c > 0, c < 10) NOT NULL)`,
			wantName: "t",
			wantCols: []Column{{Name: "c", Type: "INTEGER", NotNull: true}},
		},
		{
			name:     "default string that contains keywords",
			sql:      `CREATE TABLE t(a TEXT DEFAULT 'not null primary key', b)`,
			wantName: "t",
			wantCols: []Column{{Name: "a", Type: "TEXT"}, {Name: "b"}},
		},
		{
			name:     "without rowid",
			sql:      `CREATE TABLE t(k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID`,
			wantName: "t",
			wantCols: []Column{{Name: "k", Type: "TEXT", PK: true, selfPK: true}, {Name: "v", Type: "TEXT"}},
			wantWout: true,
		},
		{
			name:     "strict without rowid",
			sql:      `CREATE TABLE t(a, b) STRICT`,
			wantName: "t",
			wantCols: []Column{{Name: "a"}, {Name: "b"}},
		},
		{
			name:     "generated column",
			sql:      `CREATE TABLE t(a INT, b INT GENERATED ALWAYS AS (a + 1) STORED)`,
			wantName: "t",
			wantCols: []Column{{Name: "a", Type: "INT"}, {Name: "b", Type: "INT"}},
		},
		{
			name:     "comments and whitespace",
			sql:      "CREATE TABLE /* inline */ t(\n  a INTEGER, -- trailing\n  b)",
			wantName: "t",
			wantCols: []Column{{Name: "a", Type: "INTEGER"}, {Name: "b"}},
		},
		{
			name:     "escaped quotes in an identifier",
			sql:      `CREATE TABLE t("a""b" TEXT)`,
			wantName: "t",
			wantCols: []Column{{Name: `a"b`, Type: "TEXT"}},
		},
		{
			name:     "backtick and bracket identifiers",
			sql:      "CREATE TABLE t(`alpha` INT, [beta] INT)",
			wantName: "t",
			wantCols: []Column{{Name: "alpha", Type: "INT"}, {Name: "beta", Type: "INT"}},
		},
		{
			name:     "schema qualified name",
			sql:      `CREATE TABLE main.t(a)`,
			wantName: "t",
			wantCols: []Column{{Name: "a"}},
		},
		{
			name:     "if not exists",
			sql:      `CREATE TABLE IF NOT EXISTS t(a)`,
			wantName: "t",
			wantCols: []Column{{Name: "a"}},
		},
		{
			name:     "temporary table",
			sql:      `CREATE TEMP TABLE t(a)`,
			wantName: "t",
			wantCols: []Column{{Name: "a"}},
		},
		{name: "create as select", sql: `CREATE TABLE t AS SELECT 1`, wantName: "t", wantErr: "expected a column list"},
		{name: "virtual table", sql: `CREATE VIRTUAL TABLE t USING fts5(x)`, wantName: "t", wantErr: "virtual tables"},
		{name: "not a create statement", sql: `SELECT 1`, wantErr: "does not start with CREATE"},
		{name: "create index", sql: `CREATE INDEX i ON t(a)`, wantErr: "expected TABLE"},
		{name: "unbalanced parens", sql: `CREATE TABLE t(a`, wantName: "t", wantErr: "unbalanced parentheses"},
		{name: "no name", sql: `CREATE TABLE`, wantErr: "ends before the table name"},
		{name: "unterminated string", sql: `CREATE TABLE t(a DEFAULT 'x)`, wantErr: "unterminated"},
		{name: "malformed column", sql: `CREATE TABLE t((a))`, wantName: "t", wantErr: "malformed column"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, cols, without, err := parseCreateTable(tc.sql)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("parseCreateTable(%q) = %+v, want error %q", tc.sql, cols, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCreateTable(%q): %v", tc.sql, err)
			}
			if name != tc.wantName {
				t.Errorf("name = %q, want %q", name, tc.wantName)
			}
			if without != tc.wantWout {
				t.Errorf("WITHOUT ROWID = %v, want %v", without, tc.wantWout)
			}
			if len(cols) != len(tc.wantCols) {
				t.Fatalf("got %d columns %+v, want %d %+v", len(cols), cols, len(tc.wantCols), tc.wantCols)
			}
			for i, w := range tc.wantCols {
				if cols[i] != w {
					t.Errorf("column %d = %+v, want %+v", i, cols[i], w)
				}
			}
		})
	}
}

func TestTokenizeDDDDepth(t *testing.T) {
	toks, err := tokenizeDDL(`f(a, g(b), c)`)
	if err != nil {
		t.Fatal(err)
	}
	wantDepths := []int{0, 0, 1, 1, 1, 1, 2, 1, 1, 1, 0}
	if len(toks) != len(wantDepths) {
		t.Fatalf("got %d tokens %+v, want %d", len(toks), toks, len(wantDepths))
	}
	for i, w := range wantDepths {
		if toks[i].depth != w {
			t.Errorf("token %d (%q) depth = %d, want %d", i, toks[i].text, toks[i].depth, w)
		}
	}
}

func TestTokenizeDDLRejectsUnterminatedIdent(t *testing.T) {
	if _, err := tokenizeDDL(`CREATE TABLE t("oops`); err == nil {
		t.Fatal("an unterminated quoted identifier was accepted")
	}
}
