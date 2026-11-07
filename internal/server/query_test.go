package server

import (
	"bytes"
	"errors"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUnquotePlus(t *testing.T) {
	for in, want := range map[string]string{
		"a+b": "a b", "%41%62%7a%7A": "Abzz", "100%": "100%", "%zz": "%zz", "%D0%B0": "а", "plain": "plain",
	} {
		if got := unquotePlus(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// TestAPIErrors: how a read endpoint's errors become answers (nothing internal leaks into the body).
func TestAPIErrors(t *testing.T) {
	var logged bytes.Buffer
	s := &Server{log: log.New(&logged, "", 0)}
	for _, c := range []struct {
		v    any
		err  error
		code int
		body string
	}{
		{nil, notFound("no such org"), 404, `{"error":"no such org"}`},
		{nil, errNoPrompt, 501, `{"error": "prompt builder not configured"}`},
		{nil, errors.New("disk on fire"), 500, `{"error": "internal error"}`},
		{make(chan int), nil, 500, `{"error": "internal error"}`},
		{map[string]int{"a": 1}, nil, 200, `{"a":1}`},
	} {
		rec := httptest.NewRecorder()
		s.api(func(query) (any, error) { return c.v, c.err })(rec, httptest.NewRequest("GET", "/api/x?a=1", nil))
		if rec.Code != c.code || rec.Body.String() != c.body {
			t.Errorf("%v: %d %s", c.err, rec.Code, rec.Body)
		}
	}
	if !strings.Contains(logged.String(), "disk on fire") || strings.Count(logged.String(), "/api/x?a=1") != 2 {
		t.Fatalf("log: %s", &logged)
	}
}
