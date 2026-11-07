package pyfmt

// Python string semantics. The checks parse command output with str.split(), str.strip(), str.splitlines() and
// Unicode-aware regex classes; Go's strings.Fields / unicode.IsSpace / RE2 \s draw the lines slightly differently
// (\v, \x1c-\x1f, \r inside lines), and the per-host JSON must not change. Not covered: Python's \d and int() also
// take non-ASCII digits; here \d is ASCII (no command the checks run prints other digits).

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// IsSpace: Python's str.isspace() for one character (what split()/strip() and re's \s treat as whitespace).
func IsSpace(r rune) bool {
	switch {
	case r >= '\t' && r <= '\r', r >= 0x1c && r <= 0x20, r == 0x85, r == 0xa0, r == 0x1680,
		r >= 0x2000 && r <= 0x200a, r == 0x2028, r == 0x2029, r == 0x202f, r == 0x205f, r == 0x3000:
		return true
	}
	return false
}

// Fields: str.split() without arguments.
func Fields(s string) []string { return strings.FieldsFunc(s, IsSpace) }

// Strip: str.strip() without arguments.
func Strip(s string) string { return strings.TrimFunc(s, IsSpace) }

// LStrip: str.lstrip().
func LStrip(s string) string { return strings.TrimLeftFunc(s, IsSpace) }

// SplitLines: str.splitlines() — \r, \v, \f, \x1c-\x1e, \x85, U+2028/2029 end a line too, and a trailing line break
// does not produce an empty last line. nil for "".
func SplitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch r {
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			out = append(out, s[start:i])
			start = i + size
		case '\r':
			out = append(out, s[start:i])
			if i+1 < len(s) && s[i+1] == '\n' {
				size++
			}
			start = i + size
		}
		i += size
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// DecodeUTF8: bytes.decode(errors="replace") as the port does it: every undecodable byte becomes U+FFFD.
func DecodeUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		sb.WriteRune(r) // RuneError for a bad byte, n == 1
		b = b[n:]
	}
	return sb.String()
}

// Head: s[:n] in Python — n characters, not bytes.
func Head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// Last: l[-n:].
func Last[T any](l []T, n int) []T {
	if len(l) > n {
		return l[len(l)-n:]
	}
	return l
}

// IsDigit: str.isdigit() for ASCII digits (non-empty, digits only).
func IsDigit(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

var (
	pyIntRe   = regexp.MustCompile(`^[+-]?[0-9](?:_?[0-9])*$`)
	pyFloatRe = regexp.MustCompile(`(?i)^[+-]?(?:(?:[0-9](?:_?[0-9])*(?:\.(?:[0-9](?:_?[0-9])*)?)?|\.[0-9](?:_?[0-9])*)(?:e[+-]?[0-9](?:_?[0-9])*)?|inf|infinity|nan)$`)
)

// Int: int(str) — surrounding whitespace and digit underscores allowed; an error where Python raises ValueError
// (the original module then failed, so the port fails too).
func Int(s string) (int, error) {
	t := Strip(s)
	if !pyIntRe.MatchString(t) {
		return 0, errors.New("invalid literal for int() with base 10: " + strconv.Quote(s))
	}
	return strconv.Atoi(strings.ReplaceAll(t, "_", ""))
}

// Float: float(str).
func Float(s string) (float64, error) {
	t := Strip(s)
	if !pyFloatRe.MatchString(t) {
		return 0, errors.New("could not convert string to float: " + strconv.Quote(s))
	}
	if strings.Contains(strings.ToLower(t), "nan") { // float("-nan") is nan in Python; Go's parser takes no sign there
		return math.NaN(), nil
	}
	// the pattern lets through only what ParseFloat reads; out of range it gives ±Inf or 0, as Python does silently
	f, _ := strconv.ParseFloat(strings.ReplaceAll(t, "_", ""), 64)
	return f, nil
}

// Round: round(x, n) — correctly rounded on the exact binary value, as Python does.
func Round(x float64, n int) float64 {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return x
	}
	f, _ := strconv.ParseFloat(strconv.FormatFloat(x, 'f', n, 64), 64)
	return f
}

// Python's re classes are Unicode-aware: \s is str.isspace(), \w letters/digits/underscore.
const (
	pySpace    = `\t-\r\x1c-\x20\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}`
	pyWordBody = `\p{L}\p{N}_`
)

// Re compiles a Python regex: \s, \S, \w, \W get Python's Unicode meaning (outside [...] only; \d stays ASCII,
// see above).
func Re(pattern string) *regexp.Regexp {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c != '\\' || i+1 == len(pattern) {
			b.WriteByte(c)
			continue
		}
		i++
		switch pattern[i] {
		case 's':
			b.WriteString("[" + pySpace + "]")
		case 'S':
			b.WriteString("[^" + pySpace + "]")
		case 'w':
			b.WriteString("[" + pyWordBody + "]")
		case 'W':
			b.WriteString("[^" + pyWordBody + "]")
		default:
			b.WriteByte('\\')
			b.WriteByte(pattern[i])
		}
	}
	return regexp.MustCompile(b.String())
}

// Counter: collections.Counter over strings, keeping first-insertion order (most_common breaks ties by it).
type Counter struct {
	keys []string
	n    map[string]int
}

func NewCounter() *Counter { return &Counter{n: map[string]int{}} }

func (c *Counter) Add(k string, n int) {
	if _, ok := c.n[k]; !ok {
		c.keys = append(c.keys, k)
	}
	c.n[k] += n
}

func (c *Counter) Get(k string) int { return c.n[k] }
func (c *Counter) Len() int         { return len(c.keys) }
func (c *Counter) Keys() []string   { return c.keys }

func (c *Counter) Total() int {
	t := 0
	for _, k := range c.keys {
		t += c.n[k]
	}
	return t
}

// MostCommon: [[key, count], ...] by count descending, ties in insertion order; n < 0 means all.
func (c *Counter) MostCommon(n int) [][2]any {
	keys := append([]string(nil), c.keys...)
	sort.SliceStable(keys, func(i, j int) bool { return c.n[keys[i]] > c.n[keys[j]] })
	if n >= 0 && len(keys) > n {
		keys = keys[:n]
	}
	out := make([][2]any, len(keys))
	for i, k := range keys {
		out[i] = [2]any{k, c.n[k]}
	}
	return out
}

// Str formats a value the way the stored English texts were produced: whole numbers without a decimal point,
// nil as "None", booleans as "True"/"False".
func Str(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprint(t)
	case float32:
		return Str(float64(t))
	}
	return fmt.Sprint(v)
}
