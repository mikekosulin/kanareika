package report

import (
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"io"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/jsonx"
)

// A findings file is one JSON array of about a million findings on a large environment (over a gigabyte of JSON).
// It is read and written one finding at a time: nothing holds the whole text, and the strings repeated across
// findings (a CVE's title, description, vector and URL on every host that has it; host, package and target names)
// are stored once.

// decodeFindings reads a JSON array of findings (null: none) from r.
func decodeFindings(r io.Reader) ([]finding.Finding, error) {
	out := []finding.Finding{}
	err := eachElement(r, func(dec *jsontext.Decoder) error {
		out = append(out, finding.Finding{})
		return json.UnmarshalDecode(dec, &out[len(out)-1])
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// eachFinding calls fn with every finding of the JSON array in r (null: none), one at a time: f is reused, so fn
// copies what it keeps.
func eachFinding(r io.Reader, fn func(f *finding.Finding)) error {
	var f finding.Finding
	return eachElement(r, func(dec *jsontext.Decoder) error {
		f = finding.Finding{}
		if err := json.UnmarshalDecode(dec, &f); err != nil {
			return err
		}
		upgradeDenied(&f)
		fn(&f)
		return nil
	})
}

// eachElement calls decode for every element of the JSON array in r (null: none), its strings interned.
func eachElement(r io.Reader, decode func(*jsontext.Decoder) error) error {
	dec := jsontext.NewDecoder(r, jsonv1.DefaultOptionsV1(), jsonx.Strings{}.Unmarshalers())
	tok, err := dec.ReadToken()
	if err != nil {
		return err
	}
	switch tok.Kind() {
	case 'n':
		return nil
	case '[':
	default:
		return fmt.Errorf("findings: want an array, got %v", tok.Kind())
	}
	for {
		switch dec.PeekKind() {
		case ']':
			_, err := dec.ReadToken()
			return err
		case 0: // an error: ReadToken returns it
			_, err := dec.ReadToken()
			return err
		}
		if err := decode(dec); err != nil {
			return err
		}
	}
}
