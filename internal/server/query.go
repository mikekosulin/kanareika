package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

// Request parsing as the Python dashboard did it, so the same requests get the same answers.

// name: run ids and host names allowed in paths. Python's re.match with "$" also accepts one trailing newline;
// kept, so the same requests are accepted (such a name just matches no file).
var name = regexp.MustCompile(`^[A-Za-z0-9_.-]+\n?$`)

// query is urllib's parse_qs: pairs split on "&" only, "+" is a space, invalid %-escapes stay as written,
// pairs without "=" and blank values are dropped.
type query map[string][]string

func parseQS(raw string) query {
	q := query{}
	for _, pair := range strings.Split(raw, "&") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok || v == "" {
			continue
		}
		k, v = unquotePlus(k), unquotePlus(v) // v stays non-empty: unquoting never empties a string
		q[k] = append(q[k], v)
	}
	return q
}

// get: the first value, "" when absent (q.get(k, [""])[0]).
func (q query) get(k string) string {
	if v := q[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// list: the first value split on commas, empty items dropped, at most n.
func (q query) list(k string, n int) []string {
	out := []string{}
	for _, x := range strings.Split(q.get(k), ",") {
		if x != "" {
			out = append(out, x)
		}
	}
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func unquotePlus(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	if !strings.Contains(s, "%") {
		return s
	}
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b = append(b, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
			continue
		}
		b = append(b, s[i])
	}
	return pyfmt.DecodeUTF8(b)
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	}
	return c - 'a' + 10
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

// decode reads JSON keeping numbers as written, so passed-through files keep big integers.
func decode(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data")
	}
	return v, nil
}
