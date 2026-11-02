package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
)

// listeners on 127.0.0.1 plus one port that was just closed (nothing listens there). Only loopback is scanned.
func local(t *testing.T, n int) (open []int, closed int) {
	for range n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		open = append(open, l.Addr().(*net.TCPAddr).Port)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed = l.Addr().(*net.TCPAddr).Port
	l.Close()
	slices.Sort(open)
	return open, closed
}

func TestScanLocal(t *testing.T) {
	open, closed := local(t, 3)
	lo := netip.MustParseAddr("127.0.0.1")
	for name, tm := range map[string]Timing{"T3": Timings["T3"], "T5": Timings["T5"], "serial": {Timeout: time.Second, Workers: 1, Delay: time.Millisecond}} {
		got := Scan(context.Background(), []netip.Addr{lo}, append([]int{closed}, open...), tm)
		if want := map[netip.Addr][]int{lo: open}; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := Scan(ctx, []netip.Addr{lo}, open, Timings["T3"]); len(got) != 0 {
		t.Errorf("cancelled scan found %v", got)
	}
}

func TestParsePorts(t *testing.T) {
	for spec, want := range map[string][]int{
		"22":              {22},
		"443,22,80-82,22": {22, 80, 81, 82, 443},
		"T:8080, 9000":    {8080, 9000},
		"65534-":          {65534, 65535},
	} {
		got, err := ParsePorts(spec)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %v %v, want %v", spec, got, err, want)
		}
	}
	if got, _ := ParsePorts("-3"); !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Errorf("-3: %v", got)
	}
	for _, bad := range []string{"", "ssh", "U:53", "70000", "90-80", "1-2-3"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
	top := TopPorts()
	if len(top) != 1000 || !slices.Contains(top, 22) || !slices.Contains(top, 443) || !slices.Contains(top, 3389) ||
		slices.Contains(top, 6379) {
		t.Errorf("top ports: %d, %v...", len(top), top[:10])
	}
}

func TestTarget(t *testing.T) {
	for v, want := range map[string]string{"1.2.3.4": "1.2.3.4", "https://Web.Example.org:8443/x": "web.example.org",
		"10.0.0.0/24": "10.0.0.0/24", "2a00::1": "2a00::1"} {
		if got, err := Target(v); err != nil || got != want {
			t.Errorf("%q: %q %v", v, got, err)
		}
	}
	for _, bad := range []string{"-oX/tmp/x", "a b", "host;rm", "http://", ""} {
		if _, err := Target(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

func TestAddresses(t *testing.T) {
	got, err := Addresses(context.Background(), "127.0.0.0/30")
	if err != nil || len(got) != 4 || got[0].String() != "127.0.0.0" || got[3].String() != "127.0.0.3" {
		t.Errorf("/30: %v %v", got, err)
	}
	if _, err := Addresses(context.Background(), "10.0.0.0/8"); err == nil {
		t.Error("a /8 must be refused")
	}
	old := Resolver
	defer func() { Resolver = old }()
	Resolver = func(_ context.Context, h string) ([]netip.Addr, error) {
		if h != "app.example.org" {
			return nil, errors.New("no such host")
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")}, nil
	}
	if got, err := Addresses(context.Background(), "app.example.org"); err != nil || len(got) != 1 || got[0].String() != "127.0.0.2" {
		t.Errorf("name: %v %v", got, err)
	}
}

func org(external ...any) *config.Org {
	return &config.Org{ID: "acme", Hosts: []config.Host{{Name: "h", Env: "production"}},
		Data: map[string]any{"external": map[string]any{"production": external}}}
}

func ctxFor(t *testing.T, o *config.Org) (*check.Ctx, *[]string) {
	var logs []string
	return &check.Ctx{Context: context.Background(), Org: o, RunDir: t.TempDir(),
		Log: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}, &logs
}

// The finding shape of the Python module (nmap XML -> findings), here without nmap: no service names.
func TestRunExternalWithoutNmap(t *testing.T) {
	open, closed := local(t, 2)
	old := LookNmap
	defer func() { LookNmap = old }()
	LookNmap = func() (string, error) { return "", errors.New("not installed") }
	ctx, logs := ctxFor(t, org("127.0.0.1", "https://127.0.0.1/"))
	spec := fmt.Sprintf("%d,%d,%d", open[0], closed, open[1])
	f, err := RunExternal(ctx, map[string]any{"ports": spec, "timing": "T4"}, "production")
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 2 {
		t.Fatalf("findings: %+v", f)
	}
	b, _ := json.Marshal(f[0])
	var m map[string]any
	json.Unmarshal(b, &m)
	want := map[string]any{"org": "acme", "host": "external:127.0.0.1", "group": "external", "exposure": 1.0,
		"module": "network_external", "kind": "exposure", "id": "open-port-tcp-" + strconv.Itoa(open[0]), "pkg": "",
		"installed": "", "fixed": "", "status": "", "severity": "INFO", "title": fmt.Sprintf("open %d/tcp", open[0]),
		"url": "", "target": "127.0.0.1"}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s: got %v, want %v", k, m[k], v)
		}
	}
	if !reflect.DeepEqual(*logs, []string{"external 127.0.0.1: done"}) { // the URL is the same target
		t.Errorf("logs: %q", *logs)
	}
	if _, err := os.Stat(filepath.Join(ctx.RunDir, "external")); err != nil {
		t.Error(err)
	}
	// nothing to scan: no findings, no directory
	ctx, _ = ctxFor(t, org())
	if f, err := RunExternal(ctx, map[string]any{}, "production"); err != nil || f != nil {
		t.Errorf("empty: %v %v", f, err)
	}
	ctx, _ = ctxFor(t, org("-iL/etc/passwd"))
	if _, err := RunExternal(ctx, map[string]any{}, "production"); err == nil {
		t.Error("an option-like target must be refused")
	}
}

// With nmap: it gets only the open ports and the found addresses; its XML gives the service and version.
func TestRunExternalWithNmap(t *testing.T) {
	open, closed := local(t, 2)
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	script := fmt.Sprintf(`#!/bin/sh
echo "$@" > %s
while [ $# -gt 0 ]; do [ "$1" = -oX ] && out=$2; shift; done
cat > "$out" <<EOF
<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="%d"><state state="open"/><service name="ssh" product="OpenSSH" version="8.0"/></port>
<port protocol="tcp" portid="%d"><state state="open"/><service name="http"/></port>
</ports></host></nmaprun>
EOF
`, argsFile, open[0], open[1])
	nmap := filepath.Join(dir, "nmap")
	if err := os.WriteFile(nmap, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := LookNmap
	defer func() { LookNmap = old }()
	LookNmap = func() (string, error) { return nmap, nil }
	ctx, _ := ctxFor(t, org("127.0.0.1"))
	f, err := RunExternal(ctx, map[string]any{"ports": fmt.Sprintf("%d,%d,%d", closed, open[0], open[1])}, "production")
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 2 || f[0].Title != fmt.Sprintf("open %d/tcp ssh OpenSSH 8.0", open[0]) || f[0].Pkg != "ssh" ||
		f[0].Installed != "OpenSSH 8.0" || f[1].Title != fmt.Sprintf("open %d/tcp http", open[1]) {
		t.Errorf("findings: %+v", f)
	}
	args, _ := os.ReadFile(argsFile)
	wantArgs := fmt.Sprintf("-sT -sV -Pn --open -T3 -p %d,%d -oX %s -- 127.0.0.1", open[0], open[1],
		filepath.Join(ctx.RunDir, "external", "nmap-127.0.0.1.xml"))
	if strings.TrimSpace(string(args)) != wantArgs {
		t.Errorf("nmap args:\n got %s\nwant %s", args, wantArgs)
	}
}
