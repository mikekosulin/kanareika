package finding

import (
	"encoding/json"
	"strings"
	"testing"
)

// Python's msg() always stores args, also when empty: "args": {} must survive a read/write cycle, and fields this
// version does not know must too.
func TestRoundTripKeepsEmptyArgsAndUnknownFields(t *testing.T) {
	in := `{"org":"o","host":"h","kind":"misconfig","id":"x","msg":"k","args":{},"future_field":[1,2],"pkg_path":null}`
	var f Finding
	if err := json.Unmarshal([]byte(in), &f); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"args":{}`, `"future_field":[1,2]`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in %s", want, s)
		}
	}
	if strings.Contains(s, `"target_args"`) {
		t.Fatalf("absent target_args must stay absent: %s", s)
	}
}
