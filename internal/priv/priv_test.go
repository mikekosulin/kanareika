package priv

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// testdata/python.json: the same calls made with the Python implementation; the helper installed on servers and
// the commands sent must not change with the rewrite.
type golden struct {
	Helper string                       `json:"helper"`
	Cmd    map[string]map[string]string `json:"cmd"`
}

func load(t *testing.T) golden {
	b, err := os.ReadFile("testdata/python.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestHelperMatchesPython(t *testing.T) {
	if got := RenderHelper("1.2.3"); got != load(t).Helper {
		t.Fatalf("helper differs:\n%s", firstDiff(got, load(t).Helper))
	}
}

func TestCmdMatchesPython(t *testing.T) {
	g := load(t)
	for mode, want := range g.Cmd {
		calls := map[string][]string{"sshd-config": nil, "docker-cp": {strings.Repeat("a", 64), "/var/lib/rpm"},
			"docker-save": {"sha256:" + strings.Repeat("b", 64)}}
		for op, args := range calls {
			got, err := Cmd(mode, op, false, args...)
			if err != nil || got != want[op] {
				t.Fatalf("%s %s:\n go: %s\n py: %s (%v)", mode, op, got, want[op], err)
			}
		}
	}
}

func TestArgsAreChecked(t *testing.T) {
	if _, err := Cmd("sudo", "docker-save", false); err == nil {
		t.Fatal("missing arg accepted")
	}
	if c, _ := Cmd("none", "docker-save", false, "x'; rm -rf /"); !strings.Contains(c, `'x'"'"'; rm -rf /'`) {
		t.Fatal("not quoted: " + c)
	}
}

func firstDiff(a, b string) string {
	la, lb := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := range la {
		if i >= len(lb) || la[i] != lb[i] {
			if i < len(lb) {
				return "line " + string(rune('0'+i%10)) + ":\n go: " + la[i] + "\n py: " + lb[i]
			}
			return "go is longer"
		}
	}
	return "py is longer"
}
