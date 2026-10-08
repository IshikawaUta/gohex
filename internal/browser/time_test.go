package browser

import (
	"testing"
	"time"
)

func TestChromeTime(t *testing.T) {
	// 13349793600000000 µs after 1601-01-01 is 2024-01-15T12:00:00Z.
	got := chromeTime(13_349_793_600_000_000)
	want := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("chromeTime = %v, want %v", got, want)
	}
	// Sub-second precision survives the epoch shift.
	if sub := chromeTime(13_349_793_600_500_000); sub.Nanosecond() != 500_000_000 {
		t.Errorf("chromeTime fraction = %v, want .5s", sub)
	}
	for _, v := range []int64{0, -1} {
		if !chromeTime(v).IsZero() {
			t.Errorf("chromeTime(%d) = %v, want the zero time", v, chromeTime(v))
		}
	}
	// A timestamp before the Unix epoch is not a date anyone means to report.
	if !chromeTime(chromeEpochOffset - 1).IsZero() {
		t.Error("a 1601 timestamp below the Unix epoch should read as unset")
	}
}

func TestFirefoxTime(t *testing.T) {
	got := firefoxTime(UNIXMicros)
	want := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("firefoxTime = %v, want %v", got, want)
	}
	if sub := firefoxTime(UNIXMicros + 250_000); sub.Nanosecond() != 250_000_000 {
		t.Errorf("firefoxTime fraction = %v, want .25s", sub)
	}
	if !firefoxTime(0).IsZero() || !firefoxTime(-5).IsZero() {
		t.Error("unset Firefox timestamps must read as the zero time")
	}
}

func TestSafariTime(t *testing.T) {
	got := safariTime(727_012_800.0)
	want := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("safariTime = %v, want %v", got, want)
	}
	// The fractional part is carried separately so it is not lost to the
	// rounding of a large float.
	sub := safariTime(727_012_800.5)
	if sub.Nanosecond() != 500_000_000 {
		t.Errorf("safariTime fraction = %v, want .5s", sub)
	}
	if !safariTime(0).IsZero() || !safariTime(-1).IsZero() {
		t.Error("unset Safari timestamps must read as the zero time")
	}
}

// UNIXMicros is the fixture reference instant in microseconds, matching the
// value the generators write.
const UNIXMicros = int64(1_705_320_000_000_000)

// TestTimestampsAgree pins the three conversions to the same wall clock: the
// fixtures are all stamped 2024-01-15T12:00:00Z in their own epoch, so a
// mistake in any offset shows up as a disagreement here rather than as a
// plausible-looking wrong date.
func TestTimestampsAgree(t *testing.T) {
	want := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	chrome := chromeTime(UNIXMicros + chromeEpochOffset)
	firefox := firefoxTime(UNIXMicros)
	safari := safariTime(float64(UNIXMicros/1_000_000) - float64(safariEpochOffset))
	for name, got := range map[string]time.Time{
		"chrome":  chrome,
		"firefox": firefox,
		"safari":  safari,
	} {
		if !got.Equal(want) {
			t.Errorf("%s converted to %v, want %v", name, got, want)
		}
	}
}
