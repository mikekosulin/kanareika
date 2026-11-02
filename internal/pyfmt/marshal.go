package pyfmt

// encoding/json output shaped like json.dumps: for structs and for data whose numbers must stay as Go writes them
// (run files, API and MCP responses were compared with the Python version as data, number formats aside).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// Marshal: compact JSON without HTML escaping (json.dumps leaves <, >, & alone) and without a trailing newline.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// MarshalLine: json.dumps(v, ensure_ascii=ensureASCII) — one line, ", " and ": " between items; with ensureASCII
// everything non-ASCII in strings as \uXXXX (surrogate pairs above the BMP). Field order comes from the Go struct.
func MarshalLine(v any, ensureASCII bool) ([]byte, error) {
	b, err := Marshal(v)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(b)+len(b)/8)
	in := false
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case in && c == '\\':
			out = append(out, b[i:i+2]...) // Go's escapes (\" \\ \n \t \u00XX ...) are Python's too
			i += 2
			continue
		case in && ensureASCII && c >= 0x80:
			r, size := utf8.DecodeRune(b[i:])
			if r > 0xffff {
				r -= 0x10000
				out = fmt.Appendf(out, `\u%04x\u%04x`, 0xd800|(r>>10)&0x3ff, 0xdc00|r&0x3ff)
			} else {
				out = fmt.Appendf(out, `\u%04x`, r)
			}
			i += size
			continue
		case c == '"':
			in = !in
		}
		out = append(out, c)
		if !in && (c == ',' || c == ':') {
			out = append(out, ' ')
		}
		i++
	}
	return out, nil
}

// MarshalIndent: json.dumps(v, ensure_ascii=False, indent=1).
func MarshalIndent(v any) ([]byte, error) {
	b, err := Marshal(v)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", " "); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
