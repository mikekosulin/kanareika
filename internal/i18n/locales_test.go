package i18n

import (
	"maps"
	"regexp"
	"slices"
	"testing"
)

var argName = regexp.MustCompile(`\{\w+\}`)

func args(s string) []string {
	a := argName.FindAllString(s, -1)
	slices.Sort(a)
	return slices.Compact(a)
}

// TestLocalesComplete: every language has every message of English and every interface string the others have,
// with the same {placeholders}.
func TestLocalesComplete(t *testing.T) {
	once.Do(load)
	en := data[Default]
	if len(Langs()) < 3 || len(en.Messages) == 0 {
		t.Fatalf("languages %v", Langs())
	}
	ui := map[string]bool{}
	for _, l := range Langs()[1:] {
		for k := range data[l].UI {
			ui[k] = true
		}
	}
	for _, l := range Langs()[1:] {
		loc := data[l]
		for k, v := range en.Messages {
			tr, ok := loc.Messages[k]
			switch {
			case !ok || tr == "":
				t.Errorf("%s: message %s missing", l, k)
			case !slices.Equal(args(v), args(tr)):
				t.Errorf("%s: message %s: placeholders %v, English %v", l, k, args(tr), args(v))
			}
		}
		for k := range loc.Messages {
			if _, ok := en.Messages[k]; !ok {
				t.Errorf("%s: message %s is not in English", l, k)
			}
		}
		for _, k := range slices.Sorted(maps.Keys(ui)) {
			tr, ok := loc.UI[k]
			switch {
			case !ok || tr == "":
				t.Errorf("%s: interface string %q missing", l, k)
			case !slices.Equal(args(k), args(tr)):
				t.Errorf("%s: %q: placeholders %v", l, k, args(tr))
			}
		}
	}
}
