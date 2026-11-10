package server

import "testing"

// TestViewAddresses: the three places have their own addresses without .html, all of them the page itself; the
// earlier addresses go where their content went, with their query; the 0.4 page (/classic) goes to the dashboard.
func TestViewAddresses(t *testing.T) {
	s, h := newTest(t, Options{})
	for _, v := range append([]string{"", "setup", "setup/connect"}, views...) {
		r := do(h, "GET", "/"+v+"?org=acme&env=production", nil, nil)
		if r.code != 200 || r.body != string(s.page) {
			t.Errorf("/%s: %d, the page: %v", v, r.code, r.body == string(s.page))
		}
	}
	for path, want := range map[string]string{
		"/hosts?org=acme&env=production":  "/servers?org=acme&env=production",
		"/hosts":                          "/servers",
		"/access?org=acme&env=production": "/servers?show=logins&org=acme&env=production",
		"/network":                        "/servers?show=network",
		"/health":                         "/servers?show=health",
		"/packages":                       "/todo",
		"/exceptions?org=acme":            "/todo?f=accepted&org=acme",
		"/changes":                        "/history",
		"/runs?org=acme&env=production":   "/history?org=acme&env=production",
		"/setup/access":                   "/setup/connect",
	} {
		if r := do(h, "GET", path, nil, nil); r.code != 301 || r.h.Get("Location") != want {
			t.Errorf("%s: %d to %q, want 301 to %q", path, r.code, r.h.Get("Location"), want)
		}
	}
	if r := do(h, "GET", "/classic", nil, nil); r.code != 301 || r.h.Get("Location") != "/" {
		t.Errorf("/classic: %d to %q", r.code, r.h.Get("Location"))
	}
	for _, p := range []string{"/servers.html", "/servers/web-01", "/nope"} {
		if r := do(h, "GET", p, nil, nil); r.code != 404 {
			t.Errorf("%s: %d, want 404", p, r.code)
		}
	}
}
