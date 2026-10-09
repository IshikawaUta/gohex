package script

import "github.com/IshikawaUta/gohex/internal/hash"

// hashSum computes the hex digest of data with the named algorithm using
// the same registry the toolbar hash menu uses.
func hashSum(algo string, data []byte) (string, error) {
	a, err := hash.Parse(algo)
	if err != nil {
		return "", err
	}
	sum, err := hash.Sum(a, data)
	if err != nil {
		return "", err
	}
	return hash.Format(a, sum, false), nil
}
