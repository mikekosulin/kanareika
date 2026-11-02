package config

import (
	"fmt"
	"time"
)

var days = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

// ConsentProblems: why a scan must not run today (consent not yet signed or expired).
func ConsentProblems(o *Org, today time.Time) []string {
	c := o.Consent()
	d := today.Format("2006-01-02")
	var out []string
	if s := str(c, "signed"); s > d {
		out = append(out, fmt.Sprintf("consent not yet in force (signed %s)", s))
	}
	if v := str(c, "valid_until"); v < d {
		out = append(out, fmt.Sprintf("consent expired on %s", v))
	}
	return out
}

// InWindow: the scan window from consent.window; a window may cross midnight and then belongs to the day it
// started. No window = any time.
func InWindow(o *Org, now time.Time) bool {
	w := mapOf(o.Consent()["window"])
	if len(w) == 0 {
		return true
	}
	tz := str(w, "tz")
	if tz == "" {
		tz = "UTC"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return false
	}
	now = now.In(loc)
	allowed := strings_(w["days"])
	if len(allowed) == 0 {
		allowed = days
	}
	t := now.Format("15:04")
	from, to := str(w, "from"), str(w, "to")
	wd := (int(now.Weekday()) + 6) % 7 // Monday = 0
	if from <= to {
		return contains(allowed, days[wd]) && from <= t && t < to
	}
	if t >= from {
		return contains(allowed, days[wd])
	}
	if t < to {
		return contains(allowed, days[(wd+6)%7])
	}
	return false
}
