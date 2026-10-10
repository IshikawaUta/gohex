package service

import (
	"strings"
	"testing"
)

func TestCompareDocuments(t *testing.T) {
	app := newTestApp(t)
	a, err := app.OpenFile(writeFile(t, "a.bin", []byte("aaaaXXaaaa")))
	if err != nil {
		t.Fatal(err)
	}
	b, err := app.OpenFile(writeFile(t, "b.bin", []byte("aaaaBBaaab")))
	if err != nil {
		t.Fatal(err)
	}

	res, err := app.CompareDocuments(a.ID, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Identical || res.FirstDiff != 4 {
		t.Fatalf("res = %+v", res)
	}
	if len(res.Ranges) != 2 ||
		res.Ranges[0].Start != 4 || res.Ranges[0].Length != 2 ||
		res.Ranges[1].Start != 9 || res.Ranges[1].Length != 1 {
		t.Fatalf("ranges = %+v", res.Ranges)
	}
	if res.Equal != 7 || res.Differing != 3 {
		t.Fatalf("equal/differing = %d/%d", res.Equal, res.Differing)
	}
}

func TestCompareDocumentsIdentical(t *testing.T) {
	app := newTestApp(t)
	data := []byte("identical payload")
	a, err := app.OpenFile(writeFile(t, "x1.bin", data))
	if err != nil {
		t.Fatal(err)
	}
	b, err := app.OpenFile(writeFile(t, "x2.bin", data))
	if err != nil {
		t.Fatal(err)
	}
	res, err := app.CompareDocuments(a.ID, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Identical || res.FirstDiff != -1 {
		t.Fatalf("res = %+v", res)
	}
}

func TestCompareDocumentsErrors(t *testing.T) {
	app := newTestApp(t)
	a, err := app.OpenFile(writeFile(t, "only.bin", []byte("payload")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.CompareDocuments(a.ID, a.ID); err == nil ||
		!strings.Contains(err.Error(), "different documents") {
		t.Fatalf("same id: %v", err)
	}
	if _, err := app.CompareDocuments(a.ID, 9999); err == nil {
		t.Fatal("unknown id should fail")
	}
	if _, err := app.CompareDocuments(9998, a.ID); err == nil {
		t.Fatal("unknown id should fail")
	}
}
