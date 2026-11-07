package pyfmt

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestObjAccessors(t *testing.T) {
	o := O("host", "web-01", "port", 22)
	if o.Get("host") != "web-01" || o.Get("missing") != nil {
		t.Errorf("Get: %v %v", o.Get("host"), o.Get("missing"))
	}
	if !o.Has("port") || o.Has("missing") {
		t.Error("Has")
	}
	o.SetDefault("port", 2222) // kept
	o.SetDefault("org", "acme")
	o.Set("host", "web-02")
	want := O("host", "web-02", "port", 22, "org", "acme")
	if !reflect.DeepEqual(o, want) {
		t.Errorf("got %v, want %v", o, want)
	}
}

func TestObjMarshalJSONError(t *testing.T) {
	if _, err := O("f", func() {}).MarshalJSON(); err == nil {
		t.Error("a func value cannot be marshalled")
	}
}

func TestEncodeScalarsAndContainers(t *testing.T) {
	v := []any{true, false, int64(-7), json.Number("12345678901234567890123"), json.Number("1e400"),
		json.Number("2.50"), map[string]any{"b": 1, "a": nil}, []string(nil), []int{}, [0]int{}, [2]int{3, 4},
		math.NaN(), math.Inf(-1), 0.0, "q\"\\\n\r\t\b\f\x01é"}
	got, err := DumpsLine(v, true)
	if err != nil {
		t.Fatal(err)
	}
	want := `[true, false, -7, 12345678901234567890123, Infinity, 2.5, {"a": null, "b": 1}, [], [], [], [3, 4], ` +
		`NaN, -Infinity, 0.0, "q\"\\\n\r\t\b\f\u0001\u00e9"]`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	got, _ = Dumps(O("e", Obj{}, "l", [1]string{"x"}), false)
	if want := "{\n \"e\": {},\n \"l\": [\n  \"x\"\n ]\n}"; string(got) != want {
		t.Errorf("got %q", got)
	}
}

func TestEncodeErrors(t *testing.T) {
	for name, v := range map[string]any{
		"struct":           struct{}{},
		"bad float number": json.Number("1.2.3"),
		"bad int number":   json.Number("abc"),
		"inside object":    O("a", struct{}{}),
		"inside list":      []any{1, struct{}{}},
		"inside map":       map[string]any{"a": make(chan int)},
	} {
		if b, err := Dumps(v, false); err == nil {
			t.Errorf("%s: want an error, got %s", name, b)
		}
	}
	if _, err := Dumps(struct{}{}, false); err == nil || !strings.Contains(err.Error(), "cannot encode struct {}") {
		t.Errorf("error text: %v", err)
	}
}

func TestWriteJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "health.json")
	if err := WriteJSON(p, O("host", "web-01", "addr", "192.0.2.10"), true); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\n \"host\": \"web-01\",\n \"addr\": \"192.0.2.10\"\n}"; string(b) != want {
		t.Errorf("got %q", b)
	}
	if err := WriteJSON(filepath.Join(dir, "x.json"), struct{}{}, true); err == nil {
		t.Error("an encode error is returned")
	}
	if _, err := os.Stat(filepath.Join(dir, "x.json")); !os.IsNotExist(err) {
		t.Error("nothing is written on an encode error")
	}
	if err := WriteJSON(dir, O(), true); err == nil { // a directory where the file should be
		t.Error("a write error is returned")
	}
}

func TestLoadsErrors(t *testing.T) {
	for _, s := range []string{"", "{", `{1: 2}`, `{"a": }`, `[1, }`} {
		if v, err := Loads(s); err == nil {
			t.Errorf("Loads(%q) = %v, want an error", s, v)
		}
	}
}

func TestDecodeUnexpectedDelim(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(`[]`))
	if _, err := dec.Token(); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(dec); err == nil || err.Error() != "unexpected ]" {
		t.Errorf("got %v", err)
	}
}

func TestTruthyBadNumber(t *testing.T) {
	if !Truthy(json.Number("x")) {
		t.Error("a number that does not parse counts as truthy")
	}
	if Truthy(int64(0)) || !Truthy(int64(-1)) {
		t.Error("int64")
	}
}

func TestOrLen(t *testing.T) {
	if Or(nil, "", "web-01", "web-02") != "web-01" {
		t.Error("first truthy")
	}
	if got := Or(0, ""); got != "" {
		t.Errorf("last when none is truthy: %#v", got)
	}
	for _, c := range []struct {
		v    any
		want int
	}{
		{[]any{1, 2}, 2}, {map[string]any{"a": 1}, 1}, {O("a", 1, "b", 2, "c", 3), 3}, {"абв", 3}, {42, 0},
	} {
		if got := Len(c.v); got != c.want {
			t.Errorf("Len(%#v) = %d, want %d", c.v, got, c.want)
		}
	}
}

func TestOrdered(t *testing.T) {
	var o Ordered[int]
	o.Set("web-02", 2)
	o.Set("web-01", 1)
	o.Set("web-02", 20) // keeps its place
	if o.Len() != 2 || !o.Has("web-01") || o.Has("db-01") {
		t.Errorf("Len/Has: %+v", o)
	}
	if v, ok := o.Get("web-02"); !ok || v != 20 {
		t.Errorf("Get: %v %v", v, ok)
	}
	if _, ok := o.Get("db-01"); ok {
		t.Error("Get of a missing key")
	}
	b, err := json.Marshal(o)
	if err != nil || string(b) != `{"web-02":20,"web-01":1}` {
		t.Errorf("marshal: %s %v", b, err)
	}
	o.Delete("db-01") // no-op
	o.Delete("web-02")
	if !reflect.DeepEqual(o.Keys, []string{"web-01"}) || o.Len() != 1 || o.Has("web-02") {
		t.Errorf("delete: %+v", o)
	}

	var u Ordered[int]
	if err := json.Unmarshal([]byte(`{"b": 2, "a": 1, "b": 3}`), &u); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(u.Keys, []string{"b", "a"}) || u.M["b"] != 3 || u.M["a"] != 1 {
		t.Errorf("unmarshal: %+v", u)
	}
	if err := json.Unmarshal([]byte(` null `), &u); err != nil || u.Len() != 0 || u.M != nil {
		t.Errorf("null resets: %+v %v", u, err)
	}
	for _, bad := range []string{`[1]`, `{1: 2}`, `{"a": "x"}`} {
		var x Ordered[int]
		if err := x.UnmarshalJSON([]byte(bad)); err == nil {
			t.Errorf("UnmarshalJSON(%s) must fail", bad)
		}
	}
	bad := Ordered[any]{}
	bad.Set("f", func() {})
	if _, err := bad.MarshalJSON(); err == nil {
		t.Error("a func value cannot be marshalled")
	}
}

func TestMarshalErrors(t *testing.T) {
	if _, err := Marshal(func() {}); err == nil {
		t.Error("Marshal")
	}
	if _, err := MarshalLine(make(chan int), false); err == nil {
		t.Error("MarshalLine")
	}
	if _, err := MarshalIndent(func() {}); err == nil {
		t.Error("MarshalIndent")
	}
}

func TestMarshalIndent(t *testing.T) {
	got, err := MarshalIndent(struct {
		Host  string   `json:"host"`
		Addrs []string `json:"addrs"`
	}{"web-01", []string{"198.51.100.7", "<é>"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\n \"host\": \"web-01\",\n \"addrs\": [\n  \"198.51.100.7\",\n  \"<é>\"\n ]\n}"; string(got) != want {
		t.Errorf("got %q", got)
	}
}

func TestTextHelpers(t *testing.T) {
	if got := LStrip("\x1c　 a b \t"); got != "a b \t" {
		t.Errorf("lstrip: %q", got)
	}
	if got := SplitLines("a\nb"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("splitlines without a final break: %q", got)
	}
	if got := DecodeUTF8([]byte("web-01")); got != "web-01" {
		t.Errorf("valid: %q", got)
	}
	if got := DecodeUTF8([]byte("a\xffé\xc3")); got != "a�é�" {
		t.Errorf("invalid: %q", got)
	}
	if Head("абв", 3) != "абв" || Head("абвг", 3) != "абв" {
		t.Error("head of exactly n characters")
	}
	if got := Last([]int{1, 2, 3}, 2); !reflect.DeepEqual(got, []int{2, 3}) {
		t.Errorf("last: %v", got)
	}
	if got := Last([]int{1}, 2); !reflect.DeepEqual(got, []int{1}) {
		t.Errorf("last of a short list: %v", got)
	}
	for s, want := range map[string]bool{"": false, "0123": true, "12a": false, "-1": false, "١": false} {
		if IsDigit(s) != want {
			t.Errorf("IsDigit(%q) != %v", s, want)
		}
	}
	if !math.IsNaN(Round(math.NaN(), 2)) || !math.IsInf(Round(math.Inf(-1), 2), -1) {
		t.Error("round passes NaN and inf through")
	}
	// Python's float() accepts a signed "nan"; strconv.ParseFloat does not, so the port reports an error.
	for _, in := range []string{"-nan", "+NaN", " nan "} { // as Python: a signed nan is nan
		if f, err := Float(in); err != nil || !math.IsNaN(f) {
			t.Errorf("float(%q) = %v, %v", in, f, err)
		}
	}
}

func TestRe(t *testing.T) {
	re := Re(`^(\w+)\s+(\S+)\W(\d)\.`)
	if want := `^([\p{L}\p{N}_]+)[` + pySpace + `]+([^` + pySpace + `]+)[^\p{L}\p{N}_](\d)\.`; re.String() != want {
		t.Errorf("got %s", re)
	}
	m := Re(`^(\w+)\s+(\S+)\W(\d)`).FindStringSubmatch("сервер web-01!7")
	if !reflect.DeepEqual(m, []string{"сервер web-01!7", "сервер", "web-01", "7"}) {
		t.Errorf("match: %q", m)
	}
}

func TestCounter(t *testing.T) {
	c := NewCounter()
	c.Add("ssh", 1)
	c.Add("nginx", 2)
	c.Add("cron", 2)
	c.Add("ssh", 1)
	if c.Get("ssh") != 2 || c.Get("none") != 0 || c.Len() != 3 || c.Total() != 6 {
		t.Errorf("counts: %+v", c)
	}
	if !reflect.DeepEqual(c.Keys(), []string{"ssh", "nginx", "cron"}) {
		t.Errorf("keys: %v", c.Keys())
	}
	want := [][2]any{{"ssh", 2}, {"nginx", 2}, {"cron", 2}}
	if got := c.MostCommon(-1); !reflect.DeepEqual(got, want) {
		t.Errorf("most common: %v", got)
	}
	c.Add("cron", 5)
	if got := c.MostCommon(2); !reflect.DeepEqual(got, [][2]any{{"cron", 7}, {"ssh", 2}}) {
		t.Errorf("most common 2: %v", got)
	}
}
