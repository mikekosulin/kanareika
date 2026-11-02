package pyfmt

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
)

// expected values are Python 3.13's
func TestFloatRepr(t *testing.T) {
	for f, want := range map[float64]string{1e16: "1e+16", 1e15: "1000000000000000.0", 0.0001: "0.0001", 0.00001: "1e-05",
		123.456: "123.456", 1.5e300: "1.5e+300", 0.000818: "0.000818", 2: "2.0", -0.25: "-0.25", 1e22: "1e+22",
		math.Inf(1): "Infinity", 12345678901234567890: "1.2345678901234567e+19"} {
		if got := FloatRepr(f); got != want {
			t.Errorf("%v: got %s, want %s", f, got, want)
		}
	}
	if got := FloatRepr(math.Copysign(0, -1)); got != "-0.0" {
		t.Errorf("-0.0: %s", got)
	}
}

func TestStrings(t *testing.T) {
	if got := SplitLines("a\r\nb\rc\x0bd\x1ce f\n\ng\n"); !reflect.DeepEqual(got, []string{"a", "b", "c", "d", "e", "f", "", "g"}) {
		t.Errorf("splitlines: %q", got)
	}
	if SplitLines("") != nil {
		t.Error("''.splitlines() == []")
	}
	if got := Fields(" a\x1fb c　 "); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("split: %q", got)
	}
	if Head("абв", 2) != "аб" || Head("ab", 5) != "ab" {
		t.Error("head counts characters")
	}
	for s, want := range map[string]int{" 42 ": 42, //nolint:gocritic // spaces are the point
		"+7": 7, "1_000": 1000} {
		if got, err := Int(s); err != nil || got != want {
			t.Errorf("int(%q): %v %v", s, got, err)
		}
	}
	for _, bad := range []string{"", "1__0", "0x10", "4.0", "_1"} {
		if _, err := Int(bad); err == nil {
			t.Errorf("int(%q) must fail", bad)
		}
	}
	for _, bad := range []string{"1.2.3", "0x1p3", "", "."} {
		if _, err := Float(bad); err == nil {
			t.Errorf("float(%q) must fail", bad)
		}
	}
	if f, err := Float(" 1e400 "); err != nil || !math.IsInf(f, 1) {
		t.Errorf("float('1e400'): %v %v", f, err)
	}
	if Round(2.675, 2) != 2.67 || Round(0.125, 2) != 0.12 || Round(-1.005, 2) != -1 {
		t.Error("round works on the binary value, ties to even")
	}
}

func TestDumps(t *testing.T) {
	v, err := Loads(`{"b": [1, 2.50, {}], "a": "é\u0001\"", "c": [], "b": null}`)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := Dumps(v, false)
	if want := "{\n \"b\": null,\n \"a\": \"é\\u0001\\\"\",\n \"c\": []\n}"; string(got) != want {
		t.Errorf("got %s", got)
	}
	got, _ = Dumps(O("x", []any{"😀", 1e21}), true)
	if want := "{\n \"x\": [\n  \"\\ud83d\\ude00\",\n  1e+21\n ]\n}"; string(got) != want {
		t.Errorf("got %s", got)
	}
	if _, err := Loads(`{} {}`); err == nil {
		t.Error("extra data")
	}
}

func TestDumpsLine(t *testing.T) {
	v, _ := Loads(`{"ui": {"a": "x</y", "b": [1, "\u00e9"]}, "c": {}, "d": []}`)
	got, _ := DumpsLine(v, false)
	if want := `{"ui": {"a": "x</y", "b": [1, "é"]}, "c": {}, "d": []}`; string(got) != want {
		t.Errorf("got %s", got)
	}
}

func TestMarshalLine(t *testing.T) {
	v := map[string]any{"a": []any{1, "é\"\n😀<>&", nil, true}, "b": map[string]any{}}
	got, err := MarshalLine(v, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"a\": [1, \"\\u00e9\\\"\\n\\ud83d\\ude00<>&\", null, true], \"b\": {}}"; string(got) != want {
		t.Errorf("%s\nwant %s", got, want)
	}
	got, _ = MarshalLine(v, false)
	if want := "{\"a\": [1, \"é\\\"\\n😀<>&\", null, true], \"b\": {}}"; string(got) != want {
		t.Errorf("%s\nwant %s", got, want)
	}
}

func TestObjMarshalJSON(t *testing.T) {
	b, err := Marshal([]any{O("z", 1, "a", O("<", "&")), Obj(nil)})
	if err != nil || string(b) != `[{"z":1,"a":{"<":"&"}},{}]` {
		t.Errorf("%s %v", b, err)
	}
}

func TestTruthy(t *testing.T) {
	for _, v := range []any{nil, false, "", 0, 0.0, json.Number("0"), Obj{}, []any{}, []string{}, map[string]any{}} {
		if Truthy(v) {
			t.Errorf("%#v is falsy", v)
		}
	}
	for _, v := range []any{true, "x", 1, json.Number("0.5"), O("a", nil), []any{nil}, struct{}{}} {
		if !Truthy(v) {
			t.Errorf("%#v is truthy", v)
		}
	}
}
