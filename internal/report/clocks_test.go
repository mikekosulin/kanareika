package report

import (
	"reflect"
	"testing"
)

// TestClocks: a clock reads back as it was stored, packed or (what does not pack) as it is.
func TestClocks(t *testing.T) {
	p1, p9, due, empty := "P1", "P9", "2026-12-01", ""
	c := &clocks{m: map[uint64]clock{}, odd: map[uint64]*clockOf{}}
	cases := []*clockOf{
		{firstSeen: "2026-11-01", fixSince: "2026-11-02", clockStart: "2026-11-03", dueWhy: "escalated", priority: &p1,
			due: &due, accepted: true},
		{},                         // nothing set
		{firstSeen: "1969-12-31"},  // before the epoch
		{priority: &p9},            // a priority outside P1-P4
		{dueWhy: "something-else"}, // an unknown reason
		{firstSeen: "2026-11-1"},   // not a plain date
		{due: &empty},              // an empty due date
		{firstSeen: "2026-02-30"},  // no such day
	}
	for i, o := range cases {
		c.put(uint64(i), o)
	}
	if len(c.m) != 2 || len(c.odd) != 6 {
		t.Fatalf("packed %d, odd %d", len(c.m), len(c.odd))
	}
	for i, want := range cases {
		got, ok := c.lookup(uint64(i))
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("%d: got %+v, want %+v", i, got, want)
		}
	}
	if _, ok := c.lookup(99); ok || c.get(99) != nil {
		t.Error("an unknown key has no clock")
	}
	var none *clocks
	if none.get(1) != nil {
		t.Error("no clocks: nil")
	}
}
