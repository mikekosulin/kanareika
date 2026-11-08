// Package i18n renders human texts of findings, actions and fix plans from locales/<lang>.json.
//
// Data stores a message key + args and the English rendering (canonical: grouping, CLI). Other languages are
// rendered from the same key, so stored runs switch language without a rescan. Add a language = add a file.
package i18n

import (
	"encoding/json"
	"io/fs"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/mikekosulin/kanareika/assets"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

const Default = "en"

type locale struct {
	Name     string            `json:"name"` // the language in its own name: Русский, 中文
	Messages map[string]string `json:"messages"`
	UI       map[string]string `json:"ui"`
}

var (
	once sync.Once
	data map[string]locale
	// localesFS: where the locale files come from; tests replace it.
	localesFS = assets.Locales
)

func load() {
	data = map[string]locale{}
	fsys := localesFS()
	files, _ := fs.Glob(fsys, "*.json")
	for _, f := range files {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			continue
		}
		var l locale
		if json.Unmarshal(b, &l) == nil {
			data[strings.TrimSuffix(f, ".json")] = l
		}
	}
}

// Langs: the default first, then the rest by their own names, as language switchers usually list them: Latin
// script, then Cyrillic, then Chinese, Japanese, Korean (Español, Français, …, Русский, 中文, 日本語, 한국어).
func Langs() []string {
	once.Do(load)
	var out []string
	for l := range data {
		if l != Default {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := Name(out[i]), Name(out[j]); a != b {
			return a < b
		}
		return out[i] < out[j]
	})
	return append([]string{Default}, out...)
}

// Name: the language in its own name (as menus list it); the code when its file has none.
func Name(lang string) string {
	once.Do(load)
	if n := data[lang].Name; n != "" {
		return n
	}
	return lang
}

// serverOnly: message prefixes only the server renders (the agent task, the fix plan): not sent to the page.
var serverOnly = []string{"prompt.", "plan."}

// Catalog: key -> {lang: text}, the shape the dashboard uses (/api/i18n); without the server-only texts.
func Catalog() map[string]map[string]string {
	once.Do(load)
	out := map[string]map[string]string{}
	for lang, l := range data {
		for k, v := range l.Messages {
			if slices.ContainsFunc(serverOnly, func(p string) bool { return strings.HasPrefix(k, p) }) {
				continue
			}
			if out[k] == nil {
				out[k] = map[string]string{}
			}
			out[k][lang] = v
		}
	}
	return out
}

// UI: dashboard strings per language (English text -> translation); languages without any are left out.
func UI() map[string]map[string]string {
	once.Do(load)
	out := map[string]map[string]string{}
	for lang, l := range data {
		if len(l.UI) > 0 {
			out[lang] = l.UI
		}
	}
	return out
}

var placeholder = regexp.MustCompile(`\{([a-z_]+)\}`)

// T renders a message; unknown keys render as the key. An arg named <x>_key is itself a message key, rendered
// into <x> (e.g. the dmesg class inside a title).
func T(key, lang string, args map[string]any) string {
	once.Do(load)
	text, ok := data[lang].Messages[key]
	if !ok {
		if text, ok = data[Default].Messages[key]; !ok {
			return key
		}
	}
	for k, v := range args {
		if strings.HasSuffix(k, "_key") {
			if s, ok := v.(string); ok {
				args = withArg(args, strings.TrimSuffix(k, "_key"), T(s, lang, nil))
			}
		}
	}
	missing := false
	out := placeholder.ReplaceAllStringFunc(text, func(m string) string {
		v, ok := args[m[1:len(m)-1]]
		if !ok {
			missing = true
			return m
		}
		return pyfmt.Str(v)
	})
	if missing { // as Python's str.format: a missing argument leaves the template as is
		return text
	}
	return out
}

func withArg(args map[string]any, k string, v any) map[string]any {
	out := make(map[string]any, len(args)+1)
	for a, b := range args {
		out[a] = b
	}
	out[k] = v
	return out
}

// Text is a message for one field of a finding/action: the English rendering plus key and args.
type Text struct {
	Text string
	Key  string
	Args map[string]any
}

// Msg: Text in the default language.
func Msg(key string, args map[string]any) Text {
	if args == nil {
		args = map[string]any{}
	}
	return Text{Text: T(key, Default, args), Key: key, Args: args}
}

// Plain: a text without a message key (stays the same in every language).
func Plain(s string) Text { return Text{Text: s} }

// Render a stored field in lang: the stored English text when there is no key or lang is the default.
func Render(stored, key string, args map[string]any, lang string) string {
	if key == "" || lang == Default {
		return stored
	}
	return T(key, lang, args)
}
