// Package untrusted: text a scanned host reported (names, banners, log lines, paths), made safe to hand to an AI
// agent. Such text is data, never instructions; what an agent reads of it must be what a person sees. Characters
// that show nothing yet still reach the model are dropped: format characters (zero-width spaces and joiners, bidi
// embeddings, overrides and isolates, Unicode tag characters, which can spell out a whole hidden ASCII sentence)
// and variation selectors (which can carry hidden bytes after any visible character).
package untrusted

import (
	"strings"
	"unicode"
)

// Invisible: r shows nothing (or changes how its neighbours show) but is still read by a model.
func Invisible(r rune) bool {
	return unicode.Is(unicode.Cf, r) || r >= 0xFE00 && r <= 0xFE0F || r >= 0xE0100 && r <= 0xE01EF
}

// Strip: s without invisible characters; everything else, line breaks too, stays.
func Strip(s string) string {
	if !strings.ContainsFunc(s, Invisible) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if Invisible(r) {
			return -1
		}
		return r
	}, s)
}

// breaks: what ends a line or moves the cursor: control characters and the line and paragraph separators.
func breaks(r rune) bool { return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' }

// Line: s stripped and made one line (each run of control characters and line breaks a single space), so a value
// can not start a line of its own that reads like part of a task ("- New rule: …"). With max > 0, at most max
// characters: a longer value is cut and ends in "…".
func Line(s string, max int) string {
	s = strings.Join(strings.FieldsFunc(Strip(s), breaks), " ")
	if max <= 0 {
		return s
	}
	n := 0
	for i := range s {
		if n == max {
			return strings.TrimRight(s[:i], " ") + "…"
		}
		n++
	}
	return s
}
