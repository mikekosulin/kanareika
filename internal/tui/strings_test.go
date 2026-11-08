package tui

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/i18n"
)

// notWords: what stays as written in every language (priorities, abbreviations, keys, symbols).
var notWords = regexp.MustCompile(`^([A-Z0-9/+-]{1,6}|[^A-Za-z]*|[a-z]-[a-z]|Trivy|Kanareika|UTC)$`)

// uiStrings: the interface strings of the TUI's source: arguments of T(...), the titles, labels and key hints of
// its tables, forms and help, and the view names.
func uiStrings(t *testing.T) []string {
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	seen := map[string]bool{}
	add := func(e ast.Expr) {
		if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil && s != "" && !notWords.MatchString(s) {
				seen[s] = true
			}
		}
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && slices.Contains([]string{"T", "F", "FS"}, sel.Sel.Name) && len(x.Args) >= 1 {
					add(x.Args[0])
				}
				// the host card's helpers translate their first argument
				if id, ok := x.Fun.(*ast.Ident); ok && slices.Contains([]string{"kv", "section", "usage"}, id.Name) && len(x.Args) > 0 {
					add(x.Args[0])
				}
			case *ast.AssignStmt: // label = "logged in": a row label translated where it is drawn
				for i, l := range x.Lhs {
					if id, ok := l.(*ast.Ident); ok && (id.Name == "label" || id.Name == "l") && i < len(x.Rhs) {
						add(x.Rhs[i])
					}
				}
			case *ast.KeyValueExpr:
				if k, ok := x.Key.(*ast.Ident); ok && slices.Contains([]string{"title", "label", "what", "hint"}, k.Name) {
					add(x.Value)
				}
			case *ast.ValueSpec:
				for _, name := range x.Names {
					if slices.Contains([]string{"viewNames", "helpRows", "headerNames", "zoneNames", "whyTexts", "dueWhy", "groupNames",
						"sectionNames", "menuTitles", "choiceWords"}, name.Name) {
						ast.Inspect(x, func(n ast.Node) bool {
							if cl, ok := n.(*ast.CompositeLit); ok {
								for i, e := range cl.Elts {
									if kv, ok := e.(*ast.KeyValueExpr); ok {
										e = kv.Value
									}
									if name.Name == "helpRows" && len(cl.Elts) == 2 && i == 0 {
										continue // the keys themselves
									}
									add(e)
								}
							}
							return true
						})
					}
				}
			case *ast.CompositeLit: // k{"enter", "open"}: the hint, not the key
				if id, ok := x.Type.(*ast.Ident); ok && id.Name == "k" && len(x.Elts) == 2 {
					add(x.Elts[1])
				}
			}
			return true
		})
	}
	for _, s := range []string{"failed", "interrupted", "stale"} { // run states, translated as they come (T(r.State))
		seen[s] = true
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// TestEveryStringTranslated: every interface string of the TUI has a translation in every language.
func TestEveryStringTranslated(t *testing.T) {
	strs := uiStrings(t)
	if len(strs) < 100 {
		t.Fatalf("only %d strings found: the extraction is broken", len(strs))
	}
	ui := i18n.UI()
	for _, lang := range i18n.Langs()[1:] {
		var missing []string
		for _, s := range strs {
			if ui[lang][s] == "" {
				missing = append(missing, strconv.Quote(s))
			}
		}
		if len(missing) > 0 {
			t.Errorf("%s: %d untranslated:\n%s", lang, len(missing), strings.Join(missing, "\n"))
		}
	}
}
