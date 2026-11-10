package jsonx

import (
	json "encoding/json/v2"
	"strings"
	"testing"
	"unsafe"
)

func same(a, b string) bool { return unsafe.StringData(a) == unsafe.StringData(b) }

func TestStringsInternDecodedValues(t *testing.T) {
	type rec struct {
		Title string  `json:"title"`
		Desc  string  `json:"desc"`
		Opt   *string `json:"opt"`
		N     int     `json:"n"`
	}
	in := Strings{}
	var a, b rec
	doc := `{"title":"heap overflow","desc":"café \"quoted\"","opt":null,"n":1}`
	if err := json.Unmarshal([]byte(doc), &a, in.Unmarshalers()); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(doc), &b, in.Unmarshalers()); err != nil {
		t.Fatal(err)
	}
	if a.Title != "heap overflow" || a.Desc != `café "quoted"` || a.Opt != nil || a.N != 1 {
		t.Fatalf("decoded %+v", a)
	}
	if !same(a.Title, b.Title) || !same(a.Desc, b.Desc) {
		t.Fatal("a repeated string was not shared")
	}
	if len(in) != 2 {
		t.Fatalf("interned %d strings, want 2", len(in))
	}
	if s := in.Intern(strings.Clone("heap overflow")); !same(s, a.Title) {
		t.Fatal("Intern did not return the decoded copy")
	}
	if s := in.Intern("new"); s != "new" || in["new"] != "new" {
		t.Fatal("Intern did not keep a new string")
	}
}

func TestStringsKeepsDefaultErrors(t *testing.T) {
	in := Strings{}
	var v struct {
		S string `json:"s"`
	}
	if err := json.Unmarshal([]byte(`{"s": 5}`), &v, in.Unmarshalers()); err == nil {
		t.Fatal("a number into a string decoded")
	}
	if err := json.Unmarshal([]byte(`{"s": "\ud800x"}`), &v, in.Unmarshalers()); err == nil {
		t.Fatal("an invalid surrogate decoded")
	}
	if err := json.Unmarshal([]byte(`{"s": "abc`), &v, in.Unmarshalers()); err == nil {
		t.Fatal("a truncated string decoded")
	}
	var bad struct {
		S string `json:"s"`
	}
	if err := json.Unmarshal([]byte("{\"s\": \"\xff\"}"), &bad, in.Unmarshalers()); err == nil && bad.S == "\xff" {
		t.Fatal("invalid UTF-8 kept as is")
	}
}
