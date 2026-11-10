// Package jsonx: decoding helpers for the large JSON documents kanareika reads one value at a time (findings
// files, trivy reports).
package jsonx

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"unicode/utf8"
)

// Strings interns the string values decoded through it: one copy of each, however many times a document repeats it
// (a CVE's title and description on every package and host that has it).
type Strings map[string]string

// Unmarshalers: the decoding option that interns every Go string the decoder fills.
func (in Strings) Unmarshalers() json.Options {
	return json.WithUnmarshalers(json.UnmarshalFromFunc(in.unmarshal))
}

// Intern: s's interned copy.
func (in Strings) Intern(s string) string {
	if x, ok := in[s]; ok {
		return x
	}
	in[s] = s
	return s
}

// unmarshal decodes a JSON string into *s through the interner; anything else (null, a wrong type) is left to the
// default handling and its errors.
func (in Strings) unmarshal(dec *jsontext.Decoder, s *string) error {
	if dec.PeekKind() != '"' {
		return errors.ErrUnsupported
	}
	v, err := dec.ReadValue()
	if err != nil {
		return err
	}
	b := v[1 : len(v)-1]
	if bytes.IndexByte(b, '\\') >= 0 || !utf8.Valid(b) {
		b, _ = jsontext.AppendUnquote(nil, v) // cannot fail: ReadValue has validated the string
	}
	if x, ok := in[string(b)]; ok { // no allocation for a lookup by string(bytes)
		*s = x
		return nil
	}
	x := string(b)
	in[x] = x
	*s = x
	return nil
}
