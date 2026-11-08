package i18n

import (
	"io/fs"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// fakeLocales swaps the locale files for a fake catalog for the duration of the test.
func fakeLocales(t *testing.T, fsys fs.FS) {
	t.Helper()
	once.Do(load) // consume the once so later calls do not reload behind our back
	old := localesFS
	localesFS = func() fs.FS { return fsys }
	load()
	t.Cleanup(func() { localesFS = old; load() })
}

var fake = fstest.MapFS{
	"en.json": {Data: []byte(`{"messages":{
		"greet":"Hello {name}",
		"two":"{a} and {b}",
		"plain":"Nothing to fill",
		"kernel":"Kernel: {what}",
		"dmesg.oom":"out of memory",
		"only.en":"English only {n}"
	}}`)},
	"ru.json": {Data: []byte(`{"messages":{
		"greet":"Привет, {name}",
		"kernel":"Ядро: {what}",
		"dmesg.oom":"нехватка памяти"
	},"ui":{"now":"сейчас"}}`)},
	"zh.json":     {Data: []byte(`{"messages":{"greet":"你好 {name}"}}`)},
	"broken.json": {Data: []byte(`{not json`)},
	"dir.json":    {Mode: fs.ModeDir},
	"notes.txt":   {Data: []byte(`ignored`)},
}

func TestLoadSkipsBrokenFiles(t *testing.T) {
	fakeLocales(t, fake)
	if got := Langs(); !slices.Equal(got, []string{"en", "ru", "zh"}) {
		t.Fatalf("Langs() = %v", got)
	}
}

func TestCatalog(t *testing.T) {
	fakeLocales(t, fake)
	c := Catalog()
	if want := map[string]string{"en": "Hello {name}", "ru": "Привет, {name}", "zh": "你好 {name}"}; !maps.Equal(c["greet"], want) {
		t.Fatalf("greet = %v", c["greet"])
	}
	if want := map[string]string{"en": "English only {n}"}; !maps.Equal(c["only.en"], want) {
		t.Fatalf("only.en = %v", c["only.en"])
	}
	if len(c) != 6 {
		t.Fatalf("keys %v", slices.Sorted(maps.Keys(c)))
	}
}

func TestUI(t *testing.T) {
	fakeLocales(t, fake)
	ui := UI()
	if len(ui) != 1 || ui["ru"]["now"] != "сейчас" {
		t.Fatalf("UI() = %v", ui)
	}
}

func TestT(t *testing.T) {
	fakeLocales(t, fake)
	for _, c := range []struct {
		key, lang string
		args      map[string]any
		want      string
	}{
		{"greet", "en", map[string]any{"name": "web-01"}, "Hello web-01"},
		{"greet", "ru", map[string]any{"name": "web-01"}, "Привет, web-01"},
		{"greet", "de", map[string]any{"name": "web-01"}, "Hello web-01"},                  // unknown language: English
		{"only.en", "ru", map[string]any{"n": 3}, "English only 3"},                        // missing translation: English
		{"no.such.key", "ru", map[string]any{"n": 3}, "no.such.key"},                       // unknown key: the key
		{"two", "en", map[string]any{"a": 1}, "{a} and {b}"},                               // missing arg: template as is
		{"plain", "en", nil, "Nothing to fill"},                                            // no placeholders
		{"kernel", "ru", map[string]any{"what_key": "dmesg.oom"}, "Ядро: нехватка памяти"}, // nested key
		{"kernel", "en", map[string]any{"what_key": "dmesg.oom", "what": "OOM"}, "Kernel: out of memory"},
		{"kernel", "en", map[string]any{"what_key": 5, "what": "OOM"}, "Kernel: OOM"}, // non-string _key is ignored
	} {
		if got := T(c.key, c.lang, c.args); got != c.want {
			t.Errorf("T(%q, %q, %v) = %q, want %q", c.key, c.lang, c.args, got, c.want)
		}
	}
}

func TestTDoesNotMutateArgs(t *testing.T) {
	fakeLocales(t, fake)
	args := map[string]any{"what_key": "dmesg.oom"}
	T("kernel", "en", args)
	if len(args) != 1 {
		t.Fatalf("args changed: %v", args)
	}
}

func TestMsgPlainRender(t *testing.T) {
	fakeLocales(t, fake)
	m := Msg("greet", map[string]any{"name": "db-01"})
	if m.Text != "Hello db-01" || m.Key != "greet" || m.Args["name"] != "db-01" {
		t.Fatalf("Msg = %+v", m)
	}
	m = Msg("plain", nil)
	if m.Text != "Nothing to fill" || m.Args == nil || len(m.Args) != 0 {
		t.Fatalf("Msg(nil) = %+v", m)
	}
	if p := Plain("as is"); p.Text != "as is" || p.Key != "" || p.Args != nil {
		t.Fatalf("Plain = %+v", p)
	}
	args := map[string]any{"name": "db-01"}
	if got := Render("stored", "greet", args, "ru"); got != "Привет, db-01" {
		t.Fatal(got)
	}
	if got := Render("stored", "greet", args, Default); got != "stored" {
		t.Fatal(got)
	}
	if got := Render("stored", "", args, "ru"); got != "stored" {
		t.Fatal(got)
	}
}

func TestRealLocalesLoad(t *testing.T) {
	once.Do(load)
	if !slices.Contains(Langs(), "ru") || len(Catalog()) == 0 || len(UI()) == 0 {
		t.Fatalf("embedded locales: %v", Langs())
	}
}

// TestNames: every language is named in its own words; an unknown code stays a code.
func TestNames(t *testing.T) {
	once.Do(load)
	for _, l := range Langs() {
		if Name(l) == l {
			t.Errorf("%s: no \"name\" in its file", l)
		}
	}
	if Name("ru") != "Русский" || Name("xx") != "xx" {
		t.Fatal(Name("ru"), Name("xx"))
	}
}

// TestServerOnly: the agent task and the fix plan are rendered on the server: in the locales, not in /api/i18n.
func TestServerOnly(t *testing.T) {
	once.Do(load)
	for k := range Catalog() {
		if strings.HasPrefix(k, "prompt.") || strings.HasPrefix(k, "plan.") {
			t.Errorf("%s sent to the page", k)
		}
	}
	for _, k := range []string{"prompt.boundary", "plan.title"} {
		if T(k, "zh", nil) == k || T(k, "zh", nil) == T(k, Default, nil) {
			t.Errorf("%s: %q", k, T(k, "zh", nil))
		}
	}
}
