package tui

import (
	"reflect"
	"strings"
	"unicode/utf8"
)

// Text from the server (host names, package names, job output: what scanned hosts reported) reaches the terminal
// only without control characters: an escape sequence in it could clear the screen, set the clipboard (OSC 52) or
// fake a clickable zone. clean is applied to everything the client decodes; fit and safeFrame are the backstops.

// isControl: C0 (but not \n), DEL, C1.
func isControl(r rune) bool {
	return r < 0x20 && r != '\n' || r == 0x7f || r >= 0x80 && r <= 0x9f
}

// clean: s without control characters and ESC; a tab is a space, line breaks stay (the task copied keeps its lines).
func clean(s string) string {
	if !strings.ContainsFunc(s, isControl) && utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r == utf8.RuneError || isControl(r):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// scrub: every string reachable from v (a decoded API answer) cleaned in place, map keys too.
func scrub(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			scrub(v.Elem())
		}
	case reflect.Interface:
		if v.IsNil() {
			return
		}
		if e := v.Elem(); e.Kind() == reflect.String {
			if v.CanSet() {
				v.Set(reflect.ValueOf(clean(e.String())).Convert(e.Type()))
			}
		} else {
			scrub(e)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if f := v.Field(i); f.CanSet() {
				scrub(f)
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return // raw bytes (json.RawMessage): not drawn as such
		}
		for i := range v.Len() {
			scrub(v.Index(i))
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			val := reflect.New(v.Type().Elem()).Elem()
			val.Set(v.MapIndex(k))
			scrub(val)
			nk := k
			if k.Kind() == reflect.String {
				if c := clean(k.String()); c != k.String() {
					v.SetMapIndex(k, reflect.Value{})
					nk = reflect.ValueOf(c).Convert(k.Type())
				}
			}
			v.SetMapIndex(nk, val)
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(clean(v.String()))
		}
	}
}

// tame: a line about to be fitted with its line breaks and tabs as spaces, other control characters but ESC and BEL (the
// styles' and the zones' own sequences) dropped.
func tame(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool {
		return r != '\x1b' && r != '\a' && (r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f)
	}) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r == '\x1b' || r == '\a' || !(r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// safeFrame: a finished line (zones taken out) with no escape sequence but SGR (colors, bold): no OSC (clipboard,
// title, a fake zone), no cursor moves, no clearing.
func safeFrame(l string) string {
	if !strings.ContainsAny(l, "\x1b\a") {
		return l
	}
	var b strings.Builder
	for i := 0; i < len(l); {
		if l[i] != '\x1b' {
			if l[i] != '\a' { // a bell left over
				b.WriteByte(l[i])
			}
			i++
			continue
		}
		n := escLen(l[i:])
		if n > 2 && l[i+1] == '[' && l[i+n-1] == 'm' {
			b.WriteString(l[i : i+n])
		}
		i += n
	}
	return b.String()
}
