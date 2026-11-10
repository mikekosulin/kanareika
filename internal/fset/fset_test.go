package fset

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
)

// every field of a finding set: a field added to finding.Finding and not to a part fails here
func full(t *testing.T, seed int) finding.Finding {
	t.Helper()
	var f finding.Finding
	v := reflect.ValueOf(&f).Elem()
	for i := range v.NumField() {
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.String:
			fv.SetString(v.Type().Field(i).Name + string(rune('a'+seed)))
		case reflect.Int:
			fv.SetInt(int64(1 + seed))
		case reflect.Bool:
			fv.SetBool(true)
		case reflect.Pointer:
			p := reflect.New(fv.Type().Elem())
			switch p.Elem().Kind() {
			case reflect.String:
				p.Elem().SetString("x")
			case reflect.Float64:
				p.Elem().SetFloat(0.5)
			case reflect.Bool:
				p.Elem().SetBool(true)
			case reflect.Struct:
				p.Elem().Field(0).SetString("lab")
			default:
				t.Fatalf("field %s", v.Type().Field(i).Name)
			}
			fv.Set(p)
		case reflect.Map:
			if fv.Type().Elem() == reflect.TypeOf(json.RawMessage{}) {
				fv.Set(reflect.ValueOf(map[string]json.RawMessage{"k": json.RawMessage(`{"a":1}`)}))
			} else {
				fv.Set(reflect.ValueOf(map[string]any{"n": 2.0, "l": []any{"a"}}))
			}
		default:
			t.Fatalf("field %s of kind %s", v.Type().Field(i).Name, fv.Kind())
		}
	}
	return f
}

func TestRoundTrip(t *testing.T) {
	fs := []finding.Finding{full(t, 0), full(t, 1), full(t, 0)}
	fs[2].Host = "other" // the same CVE part, another rest
	s := Of(fs)
	if got, err := s.Findings(); err != nil || !reflect.DeepEqual(got, fs) {
		t.Fatalf("\n got %+v\nwant %+v", got, fs)
	}
	if len(s.CVEs) != 2 || len(s.Rests) != 3 || s.Items[0].C != s.Items[2].C {
		t.Fatalf("parts: %d cves, %d rests", len(s.CVEs), len(s.Rests))
	}
	parts, items, descs, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	fetched := 0
	lazy := &Lazy{Fetch: func(refs []int64) (map[int64]string, error) {
		out := map[int64]string{}
		for _, r := range refs {
			fetched++
			out[r] = descs[r&(1<<32-1)]
		}
		return out, nil
	}}
	b := NewBuilder()
	for ds := range 2 { // two datasets with the same parts: shared
		if err := b.AddEncoded(parts, items, lazy, int64(ds+1)); err != nil {
			t.Fatal(err)
		}
	}
	got := b.Set()
	if got.Items[0].C.Description != "" {
		t.Fatal("a description read with the parts")
	}
	want := slices.Concat(fs, fs)
	for range 2 { // the second time from the cache
		if all, err := got.Findings(); err != nil || !reflect.DeepEqual(all, want) {
			t.Fatalf("decoded: %v\n got %+v\nwant %+v", err, all, want)
		}
	}
	if fetched != 2 {
		t.Fatalf("%d descriptions fetched, want 2", fetched)
	}
	if len(got.CVEs) != 2 || len(got.Rests) != 3 || len(got.Units) != len(s.Units) {
		t.Fatalf("decoded parts: %d %d %d", len(got.CVEs), len(got.Rests), len(got.Units))
	}
	if err := b.AddEncoded(parts, items[:5], nil, 1); err == nil {
		t.Fatal("a cut items blob read")
	}
	for _, cut := range []int{0, 1, len(parts) / 2, len(parts) - 1} {
		if err := NewBuilder().AddEncoded(parts[:cut], items, nil, 1); err == nil {
			t.Fatalf("parts cut at %d read", cut)
		}
	}
}
