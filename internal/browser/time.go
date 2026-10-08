package browser

import "time"

// chromeEpochOffset is the number of microseconds between the Chromium
// epoch (1601-01-01T00:00:00Z) and the Unix epoch (1970-01-01T00:00:00Z).
const chromeEpochOffset int64 = 11644473600000000

// safariEpochOffset is the number of seconds between the Core Data epoch
// (2001-01-01T00:00:00Z) and the Unix epoch.
const safariEpochOffset int64 = 978307200

// chromeTime converts a Chromium timestamp — microseconds since 1601-01-01
// — to UTC. A zero or negative value means "no timestamp recorded" and maps
// to the zero time rather than to 1601.
func chromeTime(us int64) time.Time {
	if us <= 0 {
		return time.Time{}
	}
	unix := us - chromeEpochOffset
	if unix < 0 {
		return time.Time{}
	}
	return time.Unix(unix/1e6, (unix%1e6)*1000).UTC()
}

// firefoxTime converts a Firefox PRTime value — microseconds since the Unix
// epoch — to UTC.
func firefoxTime(us int64) time.Time {
	if us <= 0 {
		return time.Time{}
	}
	return time.Unix(us/1e6, (us%1e6)*1000).UTC()
}

// safariTime converts a Core Data timestamp — seconds since 2001-01-01,
// stored as a floating-point number — to UTC. The fraction is carried
// separately so the sub-second part is not lost to float rounding.
func safariTime(seconds float64) time.Time {
	if seconds <= 0 {
		return time.Time{}
	}
	whole := int64(seconds)
	frac := seconds - float64(whole)
	return time.Unix(whole+safariEpochOffset, int64(frac*1e9)).UTC()
}
