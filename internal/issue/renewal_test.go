package issue

import (
	"testing"
	"time"
)

// A failed automatic renewal waits 15m, 30m, 1h, 2h, 4h, then 6h between
// attempts, but never past halfway to expiry.
func TestRenewalRetryAt(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	far := now.Add(40 * 24 * time.Hour)
	for _, c := range []struct {
		failures int
		notAfter time.Time
		want     time.Duration
	}{
		{0, far, 15 * time.Minute},
		{1, far, 15 * time.Minute},
		{2, far, 30 * time.Minute},
		{3, far, time.Hour},
		{4, far, 2 * time.Hour},
		{5, far, 4 * time.Hour},
		{6, far, 6 * time.Hour},
		{40, far, 6 * time.Hour},
		{6, now.Add(4 * time.Hour), 2 * time.Hour},      // halfway to expiry
		{1, now.Add(10 * time.Minute), 5 * time.Minute}, // short-lived SVID
		{1, now.Add(-time.Minute), 0},                   // already expired
	} {
		if got := RenewalRetryAt(c.failures, now, c.notAfter).Sub(now); got != c.want {
			t.Errorf("RenewalRetryAt(%d, %v left) = %v; want %v", c.failures, c.notAfter.Sub(now), got, c.want)
		}
	}
}
