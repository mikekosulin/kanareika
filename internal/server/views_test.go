package server

import "testing"

// TestViewAddresses: each view has its own address without .html, and every one of them is the page itself; the
// 0.4 page stays at /classic.
func TestViewAddresses(t *testing.T) {
	s, h := newTest(t, Options{})
	for _, v := range append([]string{"", "setup", "setup/access"}, views...) {
		r := do(h, "GET", "/"+v+"?org=acme&env=production", nil, nil)
		if r.code != 200 || r.body != string(s.page) {
			t.Errorf("/%s: %d, the page: %v", v, r.code, r.body == string(s.page))
		}
	}
	if r := do(h, "GET", "/classic", nil, nil); r.code != 200 || r.body != string(s.classic) {
		t.Errorf("/classic: %d", r.code)
	}
	for _, p := range []string{"/hosts.html", "/hosts/web-01", "/nope"} {
		if r := do(h, "GET", p, nil, nil); r.code != 404 {
			t.Errorf("%s: %d, want 404", p, r.code)
		}
	}
}
