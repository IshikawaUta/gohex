// Package version carries the application version, overridable at build time
// via -ldflags "-X github.com/IshikawaUta/gohex/pkg/version.Version=v1.2.3".
package version

// Version is the SemVer application version.
var Version = "0.1.0"

// Product is the display name.
const Product = "GoHex"
