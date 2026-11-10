package checktest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// fakeTB records what the helpers report instead of failing the test; Fatal ends the goroutine like the real one.
type fakeTB struct {
	testing.TB
	tmp   string // TempDir answer when set
	mu    sync.Mutex
	errs  []string
	fatal bool
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) add(s string) {
	f.mu.Lock()
	f.errs = append(f.errs, s)
	f.mu.Unlock()
}

func (f *fakeTB) Errorf(format string, args ...any) { f.add(fmt.Sprintf(format, args...)) }
func (f *fakeTB) Fatalf(format string, args ...any) {
	f.add(fmt.Sprintf(format, args...))
	f.fatal = true
	runtime.Goexit()
}
func (f *fakeTB) Fatal(args ...any) {
	f.add(fmt.Sprint(args...))
	f.fatal = true
	runtime.Goexit()
}

func (f *fakeTB) TempDir() string {
	if f.tmp != "" {
		return f.tmp
	}
	return f.TB.TempDir()
}

// run calls fn with a fake TB on its own goroutine (so Fatal can end it) and returns what was reported.
func run(t *testing.T, tmp string, fn func(tb testing.TB)) *fakeTB {
	t.Helper()
	f := &fakeTB{TB: t, tmp: tmp}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(f)
	}()
	<-done
	return f
}

// expect: exactly the reports matching want (substrings, in order), and whether it ended fatally.
func (f *fakeTB) expect(t *testing.T, fatal bool, want ...string) {
	t.Helper()
	if f.fatal != fatal {
		t.Errorf("fatal %v, want %v (reports %q)", f.fatal, fatal, f.errs)
	}
	if len(f.errs) != len(want) {
		t.Fatalf("reports %q, want %d matching %q", f.errs, len(want), want)
	}
	for i, w := range want {
		if !strings.Contains(f.errs[i], w) {
			t.Errorf("report %d %q, want it to contain %q", i, f.errs[i], w)
		}
	}
}

// files writes a tree under root.
func files(t *testing.T, root string, m map[string]string) {
	t.Helper()
	for p, s := range m {
		p = filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// inDir: a fresh working directory with the tree.
func inDir(t *testing.T, m map[string]string) string {
	t.Helper()
	d := t.TempDir()
	files(t, d, m)
	t.Chdir(d)
	return d
}

func gz(s string) string { return string(gzipBytes([]byte(s))) }

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// nest: a value k brackets deep.
func nest(k int) any {
	v := any([]any{})
	for range k - 1 {
		v = []any{v}
	}
	return v
}

func ptr[T any](v T) *T { return &v }

var webHost = config.Host{Org: "acme", Name: "web-01", Group: "web", Address: "192.0.2.10", User: "audit",
	Privilege: "sudo", Exposure: 2}

// ---- golden.go

func TestRunner(t *testing.T) {
	r := &Runner{Outputs: []string{"one"}}
	if out, err := r.Run(context.Background(), webHost, "uname", 30*time.Second, true); out != "one" || err != nil {
		t.Errorf("first call: %q %v", out, err)
	}
	if _, err := r.Run(context.Background(), webHost, "id", time.Second, false); err == nil ||
		err.Error() != "unexpected call 2: id" {
		t.Errorf("second call: %v", err)
	}
	if want := []Call{{"uname", 30, true}, {"id", 1, false}}; !reflect.DeepEqual(r.Calls, want) {
		t.Errorf("calls %+v", r.Calls)
	}
	if n, err := r.Stream(context.Background(), webHost, "cat", nil, 1, time.Second, nil); n != 0 ||
		err == nil || err.Error() != "not recorded" {
		t.Errorf("stream: %d %v", n, err)
	}
}

func TestCaseHostAndNow(t *testing.T) {
	var c Case
	if err := json.Unmarshal([]byte(`{"host":{"Org":"acme","Name":"web-01","Group":"web","Address":"192.0.2.10",
		"User":"audit","Privilege":"sudo","Exposure":2},"now":"2026-03-04T05:06:07"}`), &c); err != nil {
		t.Fatal(err)
	}
	if h := c.ConfigHost(); !reflect.DeepEqual(h, webHost) {
		t.Errorf("host %+v", h)
	}
	if n := c.NowTime(t); !n.Equal(time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)) {
		t.Errorf("now %v", n)
	}
	c.Now = "yesterday"
	run(t, "", func(tb testing.TB) { c.NowTime(tb) }).expect(t, true, `cannot parse "yesterday"`)
}

func TestCases(t *testing.T) {
	inDir(t, map[string]string{
		"testdata/b/case.json": `{"host":{"Name":"web-02"},"scanner_ts":1.5}`,
		"testdata/a/case.json": `{"host":{"Name":"web-01"},"now":"2026-01-01T00:00:00"}`,
	})
	cs := Cases(t)
	if len(cs) != 2 || cs[0].Dir != filepath.Join("testdata", "a") || cs[0].Host.Name != "web-01" ||
		cs[0].Now != "2026-01-01T00:00:00" || cs[1].Host.Name != "web-02" || *cs[1].ScannerTS != 1.5 {
		t.Errorf("cases %+v", cs)
	}
}

func TestCasesFailures(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		inDir(t, nil)
		run(t, "", func(tb testing.TB) { Cases(tb) }).expect(t, true, "no cases")
	})
	t.Run("unreadable", func(t *testing.T) {
		d := inDir(t, nil)
		if err := os.MkdirAll(filepath.Join(d, "testdata", "a", "case.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		run(t, "", func(tb testing.TB) { Cases(tb) }).expect(t, true, errIsDir)
	})
	t.Run("bad json", func(t *testing.T) {
		inDir(t, map[string]string{"testdata/a/case.json": `{`})
		run(t, "", func(tb testing.TB) { Cases(tb) }).expect(t, true, "unexpected end of JSON")
	})
}

func TestRead(t *testing.T) {
	d := inDir(t, map[string]string{
		"plain.txt":     "plain",
		"packed.txt.gz": gz("packed"),
		"bad.txt.gz":    "plain text, not gzip at all",
		"cut.txt.gz":    gz(strings.Repeat("long text ", 100))[:30],
	})
	if err := os.Mkdir(filepath.Join(d, "dir.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := Read(t, "plain.txt"); got != "plain" {
		t.Errorf("plain: %q", got)
	}
	if got := Read(t, "packed.txt"); got != "packed" {
		t.Errorf("packed: %q", got)
	}
	for name, want := range map[string]string{
		"missing.txt": errNoFile,
		"bad.txt":     "gzip: invalid header",
		"cut.txt":     "unexpected EOF",
		"dir.txt":     errIsDir,
	} {
		run(t, "", func(tb testing.TB) { Read(tb, name) }).expect(t, true, want)
	}
}

func TestOrg(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		inDir(t, nil)
		if o := Org(t); o != nil {
			t.Errorf("org %+v", o)
		}
	})
	t.Run("loaded", func(t *testing.T) {
		inDir(t, map[string]string{"testdata/org.json": `{"ID":"acme","Hosts":[{"Name":"web-01","Address":"192.0.2.10",
			"Env":"production"}],"Jumps":{"bastion":"198.51.100.7"},"external":{"targets":["203.0.113.5"]}}`})
		o := Org(t)
		want := &config.Org{ID: "acme", Data: map[string]any{
			"access":   map[string]any{"jumps": map[string]any{"bastion": "198.51.100.7"}},
			"external": map[string]any{"targets": []any{"203.0.113.5"}}},
			Hosts: []config.Host{{Name: "web-01", Address: "192.0.2.10", Env: "production"}}}
		if !reflect.DeepEqual(o, want) {
			t.Errorf("org %+v", o)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		d := inDir(t, nil)
		if err := os.MkdirAll(filepath.Join(d, "testdata", "org.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		run(t, "", func(tb testing.TB) { Org(tb) }).expect(t, true, errIsDir)
	})
	t.Run("bad json", func(t *testing.T) {
		inDir(t, map[string]string{"testdata/org.json": `[1]`})
		run(t, "", func(tb testing.TB) { Org(tb) }).expect(t, true, "cannot unmarshal array")
	})
}

const wantFinding = `[{"org":"acme","host":"web-01","group":"web","exposure":2,"module":"demo","kind":"misconfig",
	"id":"demo.id","pkg":"","installed":"","fixed":"","status":"","severity":"LOW","title":"Demo","url":"",
	"target":"t","args":{}}]`

// demo: a module that runs uname and cat, logs, writes out.txt and returns one finding (or err).
func demo(err error) Module {
	return func(ctx *check.Ctx, h config.Host, cfg map[string]any, out string, _ check.Facts) ([]finding.Finding, error) {
		a, _ := ctx.SSH.Run(ctx, h, "uname -a", 30*time.Second, true)
		b, _ := ctx.SSH.Run(ctx, h, "cat /etc/hostname", 10*time.Second, false)
		ctx.Log("%s: %s|%s cfg=%d", h.Name, a, b, len(cfg))
		if e := os.WriteFile(filepath.Join(out, "out.txt"), []byte("written"), 0o644); e != nil {
			return nil, e
		}
		if err != nil {
			return nil, err
		}
		f := check.Base(h, "demo")
		f.Kind, f.ID, f.Severity, f.Title, f.Target = finding.Misconfig, "demo.id", "LOW", "Demo", "t"
		return []finding.Finding{f}, nil
	}
}

// demoCase: a case directory the demo module passes, changed by over.
func demoCase(t *testing.T, over map[string]string) Case {
	t.Helper()
	m := map[string]string{
		"testdata/org.json":               `{"ID":"acme"}`,
		"testdata/c/case.json":            `{"host":{"Org":"acme","Name":"web-01","Group":"web","Exposure":2}}`,
		"testdata/c/uname.txt":            "Linux web-01",
		"testdata/c/host.txt.gz":          gz("web-01.example.com"),
		"testdata/c/golden/findings.json": wantFinding,
		"testdata/c/golden/calls.json":    `[{"command":"uname -a","timeout":30,"check":true},{"command":"cat /etc/hostname","timeout":10,"check":false}]`,
		"testdata/c/golden/log.txt":       "web-01: Linux web-01|web-01.example.com cfg=0",
		"testdata/c/golden/out.txt":       "written",
	}
	for k, v := range over { // "\x00": remove the file
		if v == "\x00" {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	inDir(t, m)
	cs := Cases(t)
	if len(cs) != 1 {
		t.Fatalf("cases %+v", cs)
	}
	return cs[0]
}

func TestCheckPasses(t *testing.T) {
	c := demoCase(t, nil)
	run(t, "", func(tb testing.TB) { Check(tb, c, demo(nil), "uname.txt", "host.txt") }).expect(t, false)
}

func TestCheckExpectedError(t *testing.T) {
	c := demoCase(t, map[string]string{"testdata/c/golden/error.txt": "boom", "testdata/c/golden/findings.json": "\x00"})
	run(t, "", func(tb testing.TB) { Check(tb, c, demo(errors.New("boom")), "uname.txt", "host.txt") }).expect(t, false)
	// a different error, or none
	run(t, "", func(tb testing.TB) { Check(tb, c, demo(errors.New("bang")), "uname.txt", "host.txt") }).
		expect(t, true, `error: got bang, want "boom"`)
	run(t, "", func(tb testing.TB) { Check(tb, c, demo(nil), "uname.txt", "host.txt") }).
		expect(t, true, `error: got <nil>, want "boom"`)
}

func TestCheckUnexpectedError(t *testing.T) {
	c := demoCase(t, nil)
	run(t, "", func(tb testing.TB) { Check(tb, c, demo(errors.New("boom")), "uname.txt", "host.txt") }).
		expect(t, true, "unexpected error: boom")
}

func TestCheckBadCalls(t *testing.T) {
	c := demoCase(t, map[string]string{"testdata/c/golden/calls.json": "{"})
	run(t, "", func(tb testing.TB) { Check(tb, c, demo(nil), "uname.txt", "host.txt") }).
		expect(t, true, "unexpected end of JSON")
}

// Every difference is reported: findings, calls, log, a file's content, a file not written and an extra one.
func TestCheckDifferences(t *testing.T) {
	c := demoCase(t, map[string]string{
		"testdata/c/golden/findings.json": strings.Replace(wantFinding, `"LOW"`, `"HIGH"`, 1),
		"testdata/c/golden/calls.json":    `[{"command":"uname -a","timeout":30,"check":true}]`,
		"testdata/c/golden/log.txt":       "something else",
		"testdata/c/golden/out.txt":       "different",
		"testdata/c/golden/report.json":   "{}",
	})
	extra := func(ctx *check.Ctx, h config.Host, cfg map[string]any, out string, f check.Facts) ([]finding.Finding, error) {
		_ = os.WriteFile(filepath.Join(out, "extra.txt"), nil, 0o644)
		return demo(nil)(ctx, h, cfg, out, f)
	}
	run(t, "", func(tb testing.TB) { Check(tb, c, extra, "uname.txt", "host.txt") }).expect(t, false,
		"finding 0:", "calls differ", "log:", `out.txt differs: at byte 0 (len got 7, want 9)`,
		"report.json not written", "extra file extra.txt")
}

func TestFirstDiff(t *testing.T) {
	got := firstDiff("abcdef", "abcxef")
	if !strings.HasPrefix(got, "at byte 3 (len got 6, want 6)") || !strings.Contains(got, `"abcdef"`) {
		t.Errorf("%s", got)
	}
	if got := firstDiff("ab", "abc"); !strings.HasPrefix(got, "at byte 2 (len got 2, want 3)") {
		t.Errorf("%s", got)
	}
	long := strings.Repeat("x", 500)
	if got := firstDiff(long+"a", long+"b"); !strings.Contains(got, `…"`+strings.Repeat("x", 200)+`a"…`) {
		t.Errorf("window: %s", got)
	}
}

func TestCompareFindings(t *testing.T) {
	f := finding.Finding{Org: "acme", Host: "web-01", Kind: finding.Vuln, ID: "CVE-2026-0001"}
	t.Run("equal ignoring Go-only fields and empty args", func(t *testing.T) {
		run(t, "", func(tb testing.TB) {
			CompareFindings(tb, []finding.Finding{f}, `[{"org":"acme","host":"web-01","group":"","exposure":0,
				"module":"","kind":"vuln","id":"CVE-2026-0001","pkg":"","installed":"","fixed":"","status":"",
				"severity":"","title":"","url":"","target":"","args":{},"target_args":{}}]`)
		}).expect(t, false)
	})
	t.Run("Go-only field set", func(t *testing.T) {
		g := f
		g.KEV = true
		run(t, "", func(tb testing.TB) {
			CompareFindings(tb, []finding.Finding{g}, `[{"org":"acme","host":"web-01","group":"","exposure":0,
				"module":"","kind":"vuln","id":"CVE-2026-0001","pkg":"","installed":"","fixed":"","status":"",
				"severity":"","title":"","url":"","target":""}]`)
		}).expect(t, false, "finding 0:\n got exposure=0 fixed=\"\" group=\"\" host=\"web-01\" id=\"CVE-2026-0001\" installed=\"\" kev=true")
	})
	t.Run("count", func(t *testing.T) {
		run(t, "", func(tb testing.TB) { CompareFindings(tb, []finding.Finding{f}, `[]`) }).
			expect(t, false, "findings: got 1, want 0")
	})
	t.Run("bad want", func(t *testing.T) {
		run(t, "", func(tb testing.TB) { CompareFindings(tb, nil, `{`) }).expect(t, true, "unexpected end of JSON")
	})
	t.Run("unmarshalable", func(t *testing.T) {
		g := f
		g.Args = map[string]any{"c": make(chan int)}
		run(t, "", func(tb testing.TB) { CompareFindings(tb, []finding.Finding{g}, `[]`) }).
			expect(t, true, "unsupported type: chan int")
	})
}

func TestCanon(t *testing.T) {
	if got := canon(map[string]any{"b": 1, "a": "x"}); got != `a="x" b=1 ` {
		t.Errorf("%q", got)
	}
}

// ---- replay.go

func TestNorm(t *testing.T) {
	n := &Norm{Roots: [][2]string{{"/tmp/run", "$OUT"}}}
	if got := n.S("/tmp/run/x 0a1b2c3d-0000-4000-8000-00000000abcd"); got != "$OUT/x UUID" {
		t.Errorf("%q", got)
	}
	if got, want := n.Digest([]byte("in /tmp/run")), sha("in $OUT"); got != want {
		t.Errorf("text digest %s, want %s", got, want)
	}
	bin := []byte{0xff, '/', 't', 'm', 'p', '/', 'r', 'u', 'n'}
	if got, want := n.Digest(bin), sha(string(bin)); got != want {
		t.Errorf("binary digest %s, want %s (unchanged bytes)", got, want)
	}
}

func TestGzip(t *testing.T) {
	if got := string(gunzip(gzipBytes([]byte("data")))); got != "data" {
		t.Errorf("%q", got)
	}
	for in, want := range map[string]string{"plain text, not gzip at all": "invalid header", gz("long enough text")[:20]: "unexpected EOF"} {
		func() {
			defer func() {
				if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), want) {
					t.Errorf("panic %v, want %q", r, want)
				}
			}()
			gunzip([]byte(in))
		}()
	}
}

func TestListing(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits: Unix, not root")
	}
	d := t.TempDir()
	files(t, d, map[string]string{"a.txt": "in " + d, "sub/b.json.gz": gz("packed")})
	if err := os.Symlink("a.txt", filepath.Join(d, "link")); err != nil {
		t.Fatal(err)
	}
	n := &Norm{Roots: [][2]string{{d, "$OUT"}}}
	want := map[string]string{"a.txt": sha("in $OUT"), "sub/": "dir", "sub/b.json.gz": sha("packed"), "link": "-> a.txt"}
	if got := listing(d, n); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
	// an unreadable directory ends the walk
	if err := os.Mkdir(filepath.Join(d, "0locked"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(d, "0locked"), 0o755) })
	if got := listing(d, n); !reflect.DeepEqual(got, map[string]string{"0locked/": "dir"}) {
		t.Errorf("after an unreadable dir: %v", got)
	}
}

func TestFakeSSH(t *testing.T) {
	d := t.TempDir()
	files(t, d, map[string]string{"os.txt": "ID=debian"})
	c := &Replay{
		SSH: map[string]Entry{"cat /etc/os-release": {File: ptr("os.txt")}, "id": {Text: "uid=0"},
			"fail": {Err: ptr("exit 1")}},
		Stream: map[string]Entry{"tar": {Text: "0123456789"}, "bad": {Err: ptr("broken pipe")}},
	}
	s := &FakeSSH{Here: d, Case: c}
	ctx := context.Background()
	for _, c := range [][2]string{{"cat /etc/os-release", "ID=debian"}, {"id", "uid=0"}} { // in this order: calls[0] below
		cmd, want := c[0], c[1]
		if out, err := s.Run(ctx, webHost, cmd, time.Second, true); out != want || err != nil {
			t.Errorf("%s: %q %v", cmd, out, err)
		}
	}
	if _, err := s.Run(ctx, webHost, "fail", time.Second, true); err == nil || err.Error() != "exit 1" {
		t.Errorf("fail: %v", err)
	}
	if _, err := s.Run(ctx, webHost, "whoami", time.Second, true); err == nil ||
		err.Error() != "unexpected command: whoami" {
		t.Errorf("unrecorded: %v", err)
	}
	var b bytes.Buffer
	if n, err := s.Stream(ctx, webHost, "tar", &b, 100, time.Minute, nil); n != 10 || err != nil || b.String() != "0123456789" {
		t.Errorf("stream: %d %v %q", n, err, b.String())
	}
	b.Reset()
	if n, err := s.Stream(ctx, webHost, "tar", &b, 4, time.Minute, nil); n != 4 || err == nil ||
		err.Error() != "web-01: output exceeds 0 MB, aborted" || b.String() != "0123" {
		t.Errorf("stream over the limit: %d %v %q", n, err, b.String())
	}
	if n, err := s.Stream(ctx, webHost, "bad", &b, 4, time.Minute, nil); n != 0 || err == nil || err.Error() != "broken pipe" {
		t.Errorf("stream error: %d %v", n, err)
	}
	if len(s.calls) != 7 || !reflect.DeepEqual(s.calls[4], []any{"stream", "web-01", "tar", int64(100), 60}) ||
		!reflect.DeepEqual(s.calls[0], []any{"run", "web-01", "cat /etc/os-release", 1, true}) {
		t.Errorf("calls %v", s.calls)
	}
}

func TestFakeTrivy(t *testing.T) {
	here := t.TempDir()
	files(t, here, map[string]string{"r.json.gz": gz(`{"root":"@STAGE@"}`), "empty.json.gz": gz("")})
	out := t.TempDir()
	stage := filepath.Join(out, "stage")
	files(t, out, map[string]string{"stage/etc/os-release": "ID=alpine", "image.tar": "tarball"})
	c := &Replay{Trivy: map[string]Entry{"r.json": {File: ptr("r.json.gz")}, "empty.json": {File: ptr("empty.json.gz")},
		"err.json": {Err: ptr("trivy failed")}, "gone.json": {File: ptr("gone.json.gz")}}}
	n := &Norm{Roots: [][2]string{{out, "$OUT"}}}
	var calls []any
	fake := FakeTrivy(here, c, n, &calls)
	tr := func(ctx context.Context, args []string, output string, timeout time.Duration) ([]byte, error) {
		rep, err := fake(ctx, args, output, timeout)
		if err != nil {
			return nil, err
		}
		defer rep.Close()
		return io.ReadAll(rep)
	}
	ctx := context.Background()

	got, err := tr(ctx, []string{"rootfs", stage, filepath.Join(out, "image.tar"), "/", "/nonexistent-kanareika"},
		filepath.Join(out, "r.json"), 90*time.Second)
	if err != nil || string(got) != `{"root":"`+filepath.ToSlash(stage)+`"}` { // written into JSON with /
		t.Errorf("staged: %q %v", got, err)
	}
	if b, err := os.ReadFile(filepath.Join(out, "r.json.gz")); err != nil || string(gunzip(b)) != string(got) {
		t.Errorf("report written: %v", err)
	}
	want := map[string]any{
		"args":    []any{"rootfs", "$OUT/stage", "$OUT/image.tar", "/", "/nonexistent-kanareika"},
		"output":  "$OUT/r.json",
		"timeout": 90,
		"target": map[string]any{"$OUT/stage": map[string]string{"etc/": "dir", "etc/os-release": sha("ID=alpine")},
			"$OUT/image.tar": sha("tarball")},
	}
	if !reflect.DeepEqual(calls[0], want) {
		t.Errorf("call\n got %v\nwant %v", calls[0], want)
	}

	if got, err := tr(ctx, []string{"image"}, filepath.Join(out, "empty.json"), time.Second); string(got) != "{}" || err != nil {
		t.Errorf("empty report: %q %v", got, err)
	}
	var te *trivy.Error
	if _, err := tr(ctx, []string{"image"}, filepath.Join(out, "none.json"), time.Second); !errors.As(err, &te) ||
		te.Msg != "trivy image: no recorded report for none.json" {
		t.Errorf("unrecorded: %v", err)
	}
	if _, err := tr(ctx, []string{"fs"}, filepath.Join(out, "err.json"), time.Second); !errors.As(err, &te) ||
		te.Msg != "trivy failed" {
		t.Errorf("recorded error: %v", err)
	}
	if _, err := tr(ctx, []string{"fs"}, filepath.Join(out, "gone.json"), time.Second); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing report file: %v", err)
	}
	if _, err := tr(ctx, []string{"fs"}, filepath.Join(out, "no", "dir", "r.json"), time.Second); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unwritable output: %v", err)
	}
	if len(calls) != 6 {
		t.Errorf("%d calls recorded, want 6", len(calls))
	}
}

func TestHostOf(t *testing.T) {
	def := config.Host{Org: "acme", Env: "production", Group: "g", Role: "app", Address: "192.0.2.1", Port: 22,
		User: "audit", Exposure: 2, Privilege: "none"}
	if h := HostOf(nil); !reflect.DeepEqual(h, def) {
		t.Errorf("defaults %+v", h)
	}
	h := HostOf(map[string]any{"org": "acme2", "env": "staging", "name": "db-01", "group": "db", "role": "mongo",
		"exposure": 0.0, "privilege": "sudo", "address": "ignored"})
	want := config.Host{Org: "acme2", Env: "staging", Name: "db-01", Group: "db", Role: "mongo", Address: "192.0.2.1",
		Port: 22, User: "audit", Exposure: 0, Privilege: "sudo"}
	if !reflect.DeepEqual(h, want) {
		t.Errorf("given %+v", h)
	}
}

func TestAsJSON(t *testing.T) {
	if got := asJSON(t, struct{ A int }{3}); !reflect.DeepEqual(got, map[string]any{"A": 3.0}) {
		t.Errorf("%v", got)
	}
	run(t, "", func(tb testing.TB) { asJSON(tb, make(chan int)) }).expect(t, true, "unsupported type")
	run(t, "", func(tb testing.TB) { asJSON(tb, nest(10001)) }).expect(t, true, "exceeded max depth")
}

func TestLoadReplays(t *testing.T) {
	inDir(t, map[string]string{"testdata/python.json": `{"cases":[{"name":"one","ssh":{"id":{"text":"uid=0"}}},
		{"name":"two"}]}`})
	cs := LoadReplays(t)
	if len(cs) != 2 || cs[0].Name != "one" || cs[0].SSH["id"].Text != "uid=0" || cs[1].Name != "two" {
		t.Errorf("%+v", cs)
	}
	inDir(t, nil)
	run(t, "", func(tb testing.TB) { LoadReplays(tb) }).expect(t, true, errNoFile)
	inDir(t, map[string]string{"testdata/python.json": `{"cases":{}}`})
	run(t, "", func(tb testing.TB) { LoadReplays(tb) }).expect(t, true, "cannot unmarshal object")
}

func TestStrOr(t *testing.T) {
	if strOr(nil) != "<nil>" || strOr(ptr("x")) != "x" {
		t.Error("strOr")
	}
}

// replayCase: a host run that uses ssh, stream, trivy, a log line and a written file, and an org run that fails;
// with what the recording holds for it.
func replayCase(t *testing.T) (*Replay, func(*check.Ctx, ReplayRun, string) ([]finding.Finding, error)) {
	t.Helper()
	inDir(t, map[string]string{"testdata/os.txt": "ID=debian", "testdata/stage.tar": "TAR",
		"testdata/rootfs.json.gz": gz(`{"stage":"@STAGE@"}`)})
	f := finding.Finding{Org: "acme", Host: "web-01", Group: "g", Exposure: 2, Module: "demo", Kind: finding.Vuln,
		ID: "CVE-2026-0002", Target: "$OUT/hosts/web-01/x.txt"}
	c := &Replay{
		Name: "demo",
		Runs: []ReplayRun{{Host: map[string]any{"name": "web-01"}}, {}},
		SSH:  map[string]Entry{"cat /etc/os-release": {File: ptr("os.txt")}},
		// the stream command names the run dir: added once it is known
		Stream:  map[string]Entry{},
		Trivy:   map[string]Entry{"rootfs.json": {File: ptr("rootfs.json.gz")}},
		Results: []ReplayResult{{Findings: []finding.Finding{f}}, {Error: ptr("org failed in $OUT/hosts/org")}},
		Files: map[string]string{
			"hosts/": "dir", "hosts/web-01/": "dir", "hosts/org/": "dir", "stage/": "dir",
			"stage/data":                  sha("TAR"),
			"hosts/web-01/x.txt":          sha("written to $OUT"),
			"hosts/web-01/rootfs.json.gz": sha(`{"stage":"$OUT/stage"}`),
		},
		Logs: []string{"web-01: ID=debian in $OUT UUID (Ns)"},
		Calls: []any{[]any{"run", "web-01", "cat /etc/os-release", 30, true},
			[]any{"stream", "web-01", "tar -C $OUT/stage", 1 << 20, 60}},
		TrivyCalls: []any{map[string]any{"args": []any{"rootfs", "$OUT/stage"}, "output": "$OUT/hosts/web-01/rootfs.json",
			"timeout": 600, "target": map[string]any{"$OUT/stage": map[string]any{"data": sha("TAR")}}}},
	}
	call := func(ctx *check.Ctx, r ReplayRun, out string) ([]finding.Finding, error) {
		if r.Host == nil {
			return nil, fmt.Errorf("org failed in %s", out)
		}
		h := HostOf(r.Host)
		osr, err := ctx.SSH.Run(ctx, h, "cat /etc/os-release", 30*time.Second, true)
		if err != nil {
			return nil, err
		}
		stage := filepath.Join(ctx.RunDir, "stage")
		_ = os.MkdirAll(stage, 0o755)
		cmd := "tar -C " + stage
		c.Stream[cmd] = Entry{File: ptr("stage.tar")}
		w, _ := os.Create(filepath.Join(stage, "data"))
		_, err = ctx.SSH.Stream(ctx, h, cmd, w, 1<<20, time.Minute, nil)
		_ = w.Close()
		if err != nil {
			return nil, err
		}
		ctx.Log("%s: %s in %s 0a1b2c3d-0000-4000-8000-00000000abcd (12s)", h.Name, osr, ctx.RunDir)
		_ = os.WriteFile(filepath.Join(out, "x.txt"), []byte("written to "+ctx.RunDir), 0o644)
		rc, err := trivyHook(ctx, []string{"rootfs", stage}, filepath.Join(out, "rootfs.json"), 10*time.Minute)
		var rep []byte
		if err == nil {
			rep, _ = io.ReadAll(rc)
			rc.Close()
		}
		if err != nil || !strings.Contains(string(rep), filepath.ToSlash(stage)) {
			return nil, fmt.Errorf("trivy: %q %w", rep, err)
		}
		g := check.Base(h, "demo")
		g.Kind, g.ID, g.Target = finding.Vuln, "CVE-2026-0002", filepath.Join(out, "x.txt")
		return []finding.Finding{g}, nil
	}
	return c, call
}

// trivyHook: the "module's" trivy hook the replay swaps.
var trivyHook TrivyFunc = func(context.Context, []string, string, time.Duration) (io.ReadCloser, error) {
	return nil, errors.New("real trivy called")
}

func setHook(f TrivyFunc) func() {
	old := trivyHook
	trivyHook = f
	return func() { trivyHook = old }
}

func TestRunReplayPasses(t *testing.T) {
	c, call := replayCase(t)
	run(t, "", func(tb testing.TB) { RunReplay(tb, c, nil, setHook, call) }).expect(t, false)
	if _, err := trivyHook(context.Background(), nil, "", 0); err == nil || err.Error() != "real trivy called" {
		t.Errorf("hook not restored: %v", err)
	}
}

// Nothing recorded and nothing done: empty files and logs match nil ones.
func TestRunReplayEmpty(t *testing.T) {
	inDir(t, nil)
	c := &Replay{Name: "empty", Calls: []any{}, TrivyCalls: []any{}}
	run(t, "", func(tb testing.TB) {
		RunReplay(tb, c, &config.Org{ID: "acme"}, setHook, func(*check.Ctx, ReplayRun, string) ([]finding.Finding, error) {
			t.Error("no run expected")
			return nil, nil
		})
	}).expect(t, false)
}

// orgDirs: what runs without a host leave behind.
var orgDirs = map[string]string{"hosts/": "dir", "hosts/org/": "dir"}

func TestRunReplayDifferences(t *testing.T) {
	t.Run("everything", func(t *testing.T) {
		c, call := replayCase(t)
		c.Results[0].Findings[0].ID = "CVE-2026-9999"
		c.Results[1].Error = ptr("other")
		c.Files = map[string]string{}
		c.Logs = []string{"other"}
		c.Calls = []any{}
		c.TrivyCalls = []any{}
		run(t, "", func(tb testing.TB) { RunReplay(tb, c, nil, setHook, call) }).expect(t, false,
			"demo[0]: finding 0:", "demo[1]: error org failed in", "demo: files", "demo: logs",
			"demo: ssh calls", "demo: trivy calls")
	})
	t.Run("errors", func(t *testing.T) {
		inDir(t, nil)
		c := &Replay{Name: "e", Runs: []ReplayRun{{}, {}}, Results: []ReplayResult{{Error: ptr("want")}, {}},
			Files: orgDirs, Calls: []any{}, TrivyCalls: []any{}}
		i := 0
		call := func(*check.Ctx, ReplayRun, string) ([]finding.Finding, error) { //nolint:unparam // the module's signature //nolint:unparam // the module's signature
			i++
			if i == 2 {
				return nil, errors.New("got")
			}
			return nil, nil
		}
		run(t, "", func(tb testing.TB) { RunReplay(tb, c, nil, setHook, call) }).expect(t, false,
			"e[0]: error <nil>, want want", "e[1]: error got, want <nil>")
	})
	t.Run("counts and at most five findings", func(t *testing.T) {
		inDir(t, nil)
		var want, got []finding.Finding
		for i := range 8 {
			want = append(want, finding.Finding{ID: fmt.Sprint("want", i)})
			got = append(got, finding.Finding{ID: fmt.Sprint("got", i)})
		}
		c := &Replay{Name: "n", Runs: []ReplayRun{{}}, Results: []ReplayResult{{Findings: want[:7]}},
			Files: orgDirs, Calls: []any{}, TrivyCalls: []any{}}
		f := run(t, "", func(tb testing.TB) {
			RunReplay(tb, c, nil, setHook, func(*check.Ctx, ReplayRun, string) ([]finding.Finding, error) {
				return got, nil
			})
		})
		f.expect(t, false, "n[0]: 8 findings, want 7", "finding 0:", "finding 1:", "finding 2:", "finding 3:",
			"finding 4:")
	})
}

func TestRunReplayFatal(t *testing.T) {
	inDir(t, nil)
	c := &Replay{Name: "f", Runs: []ReplayRun{{Host: map[string]any{"name": "web-01"}}}, Results: []ReplayResult{{}}}
	call := func(*check.Ctx, ReplayRun, string) ([]finding.Finding, error) { //nolint:unparam // the module's signature
		return []finding.Finding{{Host: "web-01"}}, nil
	}
	t.Run("temp dir gone", func(t *testing.T) {
		run(t, filepath.Join(t.TempDir(), "gone"), func(tb testing.TB) { RunReplay(tb, c, nil, setHook, call) }).
			expect(t, true, errNoFile)
	})
	t.Run("temp dir is a file", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "file")
		files(t, filepath.Dir(p), map[string]string{"file": ""})
		run(t, p, func(tb testing.TB) { RunReplay(tb, c, nil, setHook, call) }).expect(t, true, errNotDir)
	})
	t.Run("normalization breaks the JSON", func(t *testing.T) {
		run(t, "", func(tb testing.TB) { RunReplay(tb, c, nil, setHook, call, [2]string{"web-01", `"`}) }).
			expect(t, true, "invalid character")
	})
}

// TestNormWindows: on Windows a root is also found JSON-escaped and with /, and what follows a token gets / as
// the recordings (made on Unix) have it.
func TestNormWindows(t *testing.T) {
	old := windowsPaths
	windowsPaths = true
	t.Cleanup(func() { windowsPaths = old })
	n := &Norm{Roots: [][2]string{{`C:\Users\a\Temp\001`, "$OUT"}}}
	for in, want := range map[string]string{
		`C:\Users\a\Temp\001\hosts\web-01\x.txt`:         "$OUT/hosts/web-01/x.txt",
		`{"target":"C:\\Users\\a\\Temp\\001\\hosts\\x"}`: `{"target":"$OUT/hosts/x"}`,
		`C:/Users/a/Temp/001/stage`:                      "$OUT/stage",
		`no path here`:                                   "no path here",
	} {
		if got := n.S(in); got != want {
			t.Errorf("S(%q) = %q, want %q", in, got, want)
		}
	}
}
