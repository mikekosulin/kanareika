package pyfmt

// The per-host module files (health.json, access.json, ...) are read by the dashboard and the report layer and
// diffed between runs written by the Python version, so they are written byte for byte as Python's
// json.dumps(data, indent=1[, ensure_ascii=False]) does: insertion-ordered keys (Obj), float repr, Python's escaping.
// Dumps takes dynamic values only (Obj, []any, scalars, json.Number); structs go through marshal.go.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// KV is one key of an ordered JSON object.
type KV struct {
	K string
	V any
}

// Obj: a JSON object that keeps key order (a Python dict).
type Obj []KV

// Get the value of k (nil when absent).
func (o Obj) Get(k string) any {
	for _, kv := range o {
		if kv.K == k {
			return kv.V
		}
	}
	return nil
}

// Has: k is present.
func (o Obj) Has(k string) bool {
	for _, kv := range o {
		if kv.K == k {
			return true
		}
	}
	return false
}

// Set replaces k in place or appends it (dict assignment).
func (o *Obj) Set(k string, v any) {
	for i := range *o {
		if (*o)[i].K == k {
			(*o)[i].V = v
			return
		}
	}
	*o = append(*o, KV{k, v})
}

// SetDefault: dict.setdefault — keeps an existing value.
func (o *Obj) SetDefault(k string, v any) {
	if !o.Has(k) {
		*o = append(*o, KV{k, v})
	}
}

// MarshalJSON: compact, keys in order (for Obj values inside encoding/json output, e.g. MCP responses).
func (o Obj) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, kv := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := Marshal(kv.K) // a string always encodes
		v, err := Marshal(kv.V)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// Dumps: json.dumps(v, indent=1, ensure_ascii=ensureASCII).
func Dumps(v any, ensureASCII bool) ([]byte, error) { return dumps(v, ensureASCII, 1) }

// DumpsLine: json.dumps(v, ensure_ascii=ensureASCII) — one line, ", " and ": " between items.
func DumpsLine(v any, ensureASCII bool) ([]byte, error) { return dumps(v, ensureASCII, -1) }

func dumps(v any, ascii bool, indent int) ([]byte, error) {
	var b bytes.Buffer
	if err := (encoder{&b, ascii, indent}).encode(v, 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// WriteJSON: Path.write_text(json.dumps(...)) — no trailing newline.
func WriteJSON(path string, v any, ensureASCII bool) error {
	b, err := Dumps(v, ensureASCII)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// encoder: indent < 0 writes one line.
type encoder struct {
	b      *bytes.Buffer
	ascii  bool
	indent int
}

// sep goes before the item i of a container at level; end closes a non-empty one.
func (e encoder) sep(i, level int) {
	if i > 0 {
		e.b.WriteByte(',')
	}
	if e.indent < 0 {
		if i > 0 {
			e.b.WriteByte(' ')
		}
		return
	}
	e.newline(level + 1)
}

func (e encoder) end(level int) {
	if e.indent >= 0 {
		e.newline(level)
	}
}

func (e encoder) newline(level int) {
	e.b.WriteByte('\n')
	for range level * e.indent {
		e.b.WriteByte(' ')
	}
}

func (e encoder) encode(v any, level int) error {
	b, ascii := e.b, e.ascii
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, t, ascii)
	case int:
		b.WriteString(strconv.Itoa(t))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case float64:
		b.WriteString(FloatRepr(t))
	case json.Number:
		s, err := numberRepr(string(t))
		if err != nil {
			return err
		}
		b.WriteString(s)
	case Obj:
		if len(t) == 0 {
			b.WriteString("{}")
			return nil
		}
		b.WriteByte('{')
		for i, kv := range t {
			e.sep(i, level)
			writeString(b, kv.K, ascii)
			b.WriteString(": ")
			if err := e.encode(kv.V, level+1); err != nil {
				return err
			}
		}
		e.end(level)
		b.WriteByte('}')
	case map[string]any: // only for data that Python had sorted anyway
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		o := make(Obj, len(keys))
		for i, k := range keys {
			o[i] = KV{k, t[k]}
		}
		return e.encode(o, level)
	default:
		rv := reflect.ValueOf(v)
		if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
			return fmt.Errorf("pyfmt: cannot encode %T", v)
		}
		if rv.Kind() == reflect.Slice && rv.IsNil() { // a nil slice is a list that was never filled: []
			b.WriteString("[]")
			return nil
		}
		if rv.Len() == 0 {
			b.WriteString("[]")
			return nil
		}
		b.WriteByte('[')
		for i := range rv.Len() {
			e.sep(i, level)
			if err := e.encode(rv.Index(i).Interface(), level+1); err != nil {
				return err
			}
		}
		e.end(level)
		b.WriteByte(']')
	}
	return nil
}

const hex = "0123456789abcdef"

func writeU(b *bytes.Buffer, r rune) {
	b.WriteString(`\u`)
	b.WriteByte(hex[r>>12&0xf])
	b.WriteByte(hex[r>>8&0xf])
	b.WriteByte(hex[r>>4&0xf])
	b.WriteByte(hex[r&0xf])
}

// writeString: Python's encoder — short escapes for \b \f \n \r \t, \u00XX for other controls; with ensure_ascii
// everything outside ' '..'~' becomes \uXXXX (surrogate pairs above the BMP). Invalid UTF-8 (Python strings never
// have it: the SSH layer decodes with errors="replace") is written as U+FFFD.
func writeString(b *bytes.Buffer, s string, ascii bool) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				writeU(b, r)
			case ascii && r > 0x7e:
				if r > 0xffff {
					r -= 0x10000
					writeU(b, 0xd800|(r>>10)&0x3ff)
					writeU(b, 0xdc00|r&0x3ff)
				} else {
					writeU(b, r)
				}
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// FloatRepr: Python's repr(float) — shortest round-trip digits, fixed notation for 1e-4 <= |x| < 1e16 (always with
// a decimal point), otherwise d.ddde+XX; NaN/Infinity as json.dumps writes them.
func FloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	sign := ""
	if s[0] == '-' {
		sign, s = "-", s[1:]
	}
	mant, expS, _ := strings.Cut(s, "e")
	exp, _ := strconv.Atoi(expS)
	digits := strings.Replace(mant, ".", "", 1)
	if exp >= -4 && exp < 16 {
		if exp < 0 {
			return sign + "0." + strings.Repeat("0", -exp-1) + digits
		}
		if len(digits) <= exp+1 {
			return sign + digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
		}
		return sign + digits[:exp+1] + "." + digits[exp+1:]
	}
	m := digits[:1]
	if len(digits) > 1 {
		m += "." + digits[1:]
	}
	es := "+"
	if exp < 0 {
		es, exp = "-", -exp
	}
	e := strconv.Itoa(exp)
	if len(e) < 2 {
		e = "0" + e
	}
	return sign + m + "e" + es + e
}

// numberRepr: how a JSON number read by json.loads is written back: ints as ints, anything with a fraction or
// exponent as a float.
func numberRepr(lit string) (string, error) {
	if strings.ContainsAny(lit, ".eE") {
		f, err := strconv.ParseFloat(lit, 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return "", err
		}
		return FloatRepr(f), nil
	}
	n, ok := new(big.Int).SetString(lit, 10)
	if !ok {
		return "", fmt.Errorf("pyfmt: bad number %q", lit)
	}
	return n.String(), nil
}

// Loads: json.loads keeping key order (objects become Obj, numbers json.Number). A repeated key keeps its first
// position and the last value, as a Python dict does.
func Loads(data string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(data))
	dec.UseNumber()
	v, err := Decode(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("extra data")
	}
	return v, nil
}

// Decode reads the next value of dec as Loads does (numbers are json.Number only if dec uses UseNumber).
func Decode(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if t, ok := tok.(json.Delim); ok {
		switch t {
		case '{':
			o := Obj{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				v, err := Decode(dec)
				if err != nil {
					return nil, err
				}
				o.Set(kt.(string), v)
			}
			_, err := dec.Token()
			return o, err
		case '[':
			l := []any{}
			for dec.More() {
				v, err := Decode(dec)
				if err != nil {
					return nil, err
				}
				l = append(l, v)
			}
			_, err := dec.Token()
			return l, err
		}
		return nil, fmt.Errorf("unexpected %v", t)
	}
	return tok, nil
}

// Truthy: Python's bool() of a decoded JSON value (or of the Go value standing for one).
func Truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case json.Number:
		f, err := t.Float64()
		return err != nil || f != 0
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	case Obj:
		return len(t) > 0
	case []any:
		return len(t) > 0
	case []string:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return true
}

// Or: Python's "a or b or ...": the first truthy value, else the last.
func Or(vs ...any) any {
	for _, v := range vs[:len(vs)-1] {
		if Truthy(v) {
			return v
		}
	}
	return vs[len(vs)-1]
}

// Len: len() of a decoded JSON value (lists, objects, strings in characters); 0 for anything else.
func Len(v any) int {
	switch t := v.(type) {
	case []any:
		return len(t)
	case map[string]any:
		return len(t)
	case Obj:
		return len(t)
	case string:
		return utf8.RuneCountInString(t)
	}
	return 0
}

// O builds an Obj from alternating keys and values: O("a", 1, "b", 2).
func O(kv ...any) Obj {
	o := make(Obj, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		o = append(o, KV{kv[i].(string), kv[i+1]})
	}
	return o
}

// Ordered is a typed JSON object that keeps its key order (a Python dict as a struct field): run.json's
// hosts_failed / module_errors list hosts in the order the scan finished them.
type Ordered[V any] struct {
	Keys []string
	M    map[string]V
}

func (o *Ordered[V]) Len() int { return len(o.Keys) }

func (o *Ordered[V]) Has(k string) bool { _, ok := o.M[k]; return ok }

func (o *Ordered[V]) Get(k string) (V, bool) { v, ok := o.M[k]; return v, ok }

// Set appends a new key at the end; an existing key keeps its place.
func (o *Ordered[V]) Set(k string, v V) {
	if o.M == nil {
		o.M = map[string]V{}
	}
	if _, ok := o.M[k]; !ok {
		o.Keys = append(o.Keys, k)
	}
	o.M[k] = v
}

func (o *Ordered[V]) Delete(k string) {
	if _, ok := o.M[k]; !ok {
		return
	}
	delete(o.M, k)
	for i, x := range o.Keys {
		if x == k {
			o.Keys = append(o.Keys[:i:i], o.Keys[i+1:]...)
			break
		}
	}
}

func (o Ordered[V]) MarshalJSON() ([]byte, error) {
	out := make(Obj, len(o.Keys))
	for i, k := range o.Keys {
		out[i] = KV{k, o.M[k]}
	}
	return out.MarshalJSON()
}

func (o *Ordered[V]) UnmarshalJSON(b []byte) error {
	*o = Ordered[V]{}
	if string(bytes.TrimSpace(b)) == "null" {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return fmt.Errorf("expected a JSON object")
	}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return err
		}
		var v V
		if err := d.Decode(&v); err != nil {
			return err
		}
		o.Set(t.(string), v)
	}
	return nil
}
