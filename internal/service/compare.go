package service

import (
	"errors"
	"fmt"

	"github.com/IshikawaUta/gohex/internal/compare"
)

// maxCompareRanges caps one comparison result (bytes counts stay exact
// beyond the cap; only the range list is truncated).
const maxCompareRanges = compare.DefaultMaxRanges

// CompareDocuments byte-compares two open documents and reports the
// differing ranges, the first differing offset and equal/differing byte
// counts. Both documents are read-only sources; nothing is audited
// because no file is opened (the documents already have open records).
func (a *App) CompareDocuments(idA, idB int64) (compare.Result, error) {
	if idA == idB {
		return compare.Result{}, errors.New("service: compare: pick two different documents")
	}
	d1, err := a.lookup(idA)
	if err != nil {
		return compare.Result{}, err
	}
	d2, err := a.lookup(idB)
	if err != nil {
		return compare.Result{}, err
	}
	res, err := compare.Compare(d1.document, d2.document,
		d1.document.Size(), d2.document.Size(), maxCompareRanges)
	if err != nil {
		return compare.Result{}, fmt.Errorf("service: %w", err)
	}
	return *res, nil
}
