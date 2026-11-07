package finding

import (
	"encoding/json"
	"math"
	"testing"
)

func TestUnmarshalErrors(t *testing.T) {
	for _, in := range []string{`[1]`, `"web-01"`, `{"org":1}`, `{"org":`} {
		var f Finding
		if err := json.Unmarshal([]byte(in), &f); err == nil {
			t.Errorf("%s: no error", in)
		}
	}
	var f Finding
	if err := json.Unmarshal([]byte(`null`), &f); err != nil || f.Extra != nil {
		t.Fatalf("null: %v %+v", err, f)
	}
}

func TestMarshalErrors(t *testing.T) {
	nan := math.NaN()
	for name, f := range map[string]Finding{
		"plain":      {Org: "acme", EPSS: &nan},
		"with extra": {Org: "acme", EPSS: &nan, Extra: map[string]json.RawMessage{"future": []byte(`1`)}},
	} {
		if b, err := json.Marshal(f); err == nil {
			t.Errorf("%s: no error, got %s", name, b)
		}
	}
	// Extra never overrides a known field.
	b, err := json.Marshal(Finding{Org: "acme", Extra: map[string]json.RawMessage{"org": []byte(`"other"`)}})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m["org"] != "acme" {
		t.Fatalf("org = %v (%v) in %s", m["org"], err, b)
	}
}

func TestPriorityAndDueOr(t *testing.T) {
	var f Finding
	if f.PriorityOr() != "" || f.DueOr() != "" {
		t.Fatalf("unset: %q %q", f.PriorityOr(), f.DueOr())
	}
	p, d := "P1", "2026-12-01"
	f.Priority, f.Due = &p, &d
	if f.PriorityOr() != "P1" || f.DueOr() != "2026-12-01" {
		t.Fatalf("set: %q %q", f.PriorityOr(), f.DueOr())
	}
}
