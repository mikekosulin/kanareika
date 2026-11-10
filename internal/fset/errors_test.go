package fset

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
)

// TestUnencodable: a finding whose Args JSON can't hold (made in code, never read from a file) is an error to Add
// and a panic to Of, not a finding silently dropped.
func TestUnencodable(t *testing.T) {
	f := finding.Finding{Host: "h", Kind: finding.Misconfig, ID: "x", Args: map[string]any{"f": func() {}}}
	if err := NewBuilder().Add(&f); err == nil {
		t.Fatal("added")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("Of took it")
		}
	}()
	Of([]finding.Finding{f})
}

// TestBrokenEncoded: stored parts that don't read back are errors, whatever is wrong with them.
func TestBrokenEncoded(t *testing.T) {
	s := Of([]finding.Finding{{Host: "h", Kind: finding.Vuln, ID: "CVE-1", Pkg: "p"}})
	parts, items, _, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	uv := func(b []byte, n int) []byte { return binary.AppendUvarint(b, uint64(n)) }
	one := func(js string) []byte { return append(uv(uv(nil, 1), len(js)), js...) }
	for _, c := range []struct {
		name         string
		parts, items []byte
		want         string
	}{
		{"trailing bytes", append(append([]byte{}, parts...), 7), items, "after the parts"},
		{"bad CVE", append(one(`{"id":`), uv(nil, 0)...), nil, "unexpected end"},
		{"bad rest", append(uv(nil, 0), one(`[`)...), nil, "unexpected end"},
		{"item out of range", parts, append(append([]byte{}, items...), 9, 0, 0, 0, 0, 0, 0, 0), "out of range"},
		{"items cut", parts, items[:5], "items"},
	} {
		err := NewBuilder().AddEncoded(c.parts, c.items, nil, 1)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// TestLazyDescriptions: descriptions left out are fetched once; one the store no longer has is empty, and a fetch
// that fails is the error of Descriptions and of Encode.
func TestLazyDescriptions(t *testing.T) {
	s := Of([]finding.Finding{
		{Host: "h", Kind: finding.Vuln, ID: "CVE-1", Pkg: "p", Description: "one"},
		{Host: "h", Kind: finding.Vuln, ID: "CVE-2", Pkg: "p", Description: "two"},
	})
	parts, items, _, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	l := &Lazy{Fetch: func(refs []int64) (map[int64]string, error) {
		calls++
		return map[int64]string{refs[0]: "fetched"}, nil // the other one is gone
	}}
	b := NewBuilder()
	if err := b.AddEncoded(parts, items, l, 3); err != nil {
		t.Fatal(err)
	}
	got := b.Set()
	for range 2 {
		ds, err := Descriptions(got.CVEs)
		if err != nil || len(ds) != 2 || ds[0]+ds[1] != "fetched" {
			t.Fatalf("%q %v", ds, err)
		}
	}
	if calls != 1 {
		t.Fatalf("%d fetches", calls)
	}
	bad := &Lazy{Fetch: func([]int64) (map[int64]string, error) { return nil, errors.New("gone") }}
	b = NewBuilder()
	if err := b.AddEncoded(parts, items, bad, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := Descriptions(b.Set().CVEs); err == nil {
		t.Fatal("no error from the fetch")
	}
	if _, _, _, err := b.Set().Encode(); err == nil {
		t.Fatal("encoded without its descriptions")
	}
}

// TestAllStops: All stops when the caller does; a rest without a priority or due date reads as "".
func TestAllStops(t *testing.T) {
	s := Of([]finding.Finding{{Host: "a", Kind: finding.Vuln, ID: "1"}, {Host: "b", Kind: finding.Vuln, ID: "2"}})
	n := 0
	for f := range s.All() {
		n++
		if f.Host == "a" {
			break
		}
	}
	if n != 1 || s.Len() != 2 {
		t.Fatalf("%d of %d", n, s.Len())
	}
	if r := s.Items[0].Rest; r.PriorityOr() != "" || r.DueOr() != "" {
		t.Fatalf("%q %q", r.PriorityOr(), r.DueOr())
	}
}
