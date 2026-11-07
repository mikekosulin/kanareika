package network

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// The default resolver answers an address literal itself, without a lookup (as an IPv4-mapped address).
func TestDefaultResolverLiteral(t *testing.T) {
	got, err := Resolver(context.Background(), "127.0.0.1")
	if err != nil || len(got) != 1 || got[0].Unmap() != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("got %v, %v", got, err)
	}
}

func TestDefaultLookNmap(t *testing.T) {
	got, err := LookNmap()
	want, werr := exec.LookPath("nmap")
	if got != want || (err == nil) != (werr == nil) {
		t.Errorf("got %q %v, want %q %v", got, err, want, werr)
	}
}

func TestAddressesResolverFailures(t *testing.T) {
	old := Resolver
	defer func() { Resolver = old }()
	Resolver = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	if _, err := Addresses(context.Background(), "web-01.example.com"); err == nil || err.Error() != "no such host" {
		t.Errorf("err %v", err)
	}
	Resolver = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	if _, err := Addresses(context.Background(), "web-01.example.com"); err == nil ||
		err.Error() != "web-01.example.com: no IPv4 address" {
		t.Errorf("err %v", err)
	}
}

// A cancelled scan stops feeding probes and probes nothing; zero workers still means one.
func TestScanCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ports := make([]int, 1000)
	for i := range ports {
		ports[i] = i + 1
	}
	got := Scan(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ports, Timing{Delay: time.Hour})
	if len(got) != 0 {
		t.Errorf("found %v", got)
	}
}

// No answer within the timeout, after every retry, is filtered. A deadline already passed times out before any
// packet is sent.
func TestProbeTimeout(t *testing.T) {
	if probe(context.Background(), netip.MustParseAddr("127.0.0.1"), 9, Timing{Timeout: time.Nanosecond, Retries: 2}) {
		t.Error("open")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	open, _ := local(t, 1)
	if probe(ctx, netip.MustParseAddr("127.0.0.1"), open[0], Timing{Timeout: time.Second}) {
		t.Error("a cancelled probe connected")
	}
}

// fakeNmap: a shell script standing in for nmap; body runs with $out set to the -oX path.
func fakeNmap(t *testing.T, body string) (path, argsFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a shell script stands in for nmap")
	}
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	script := fmt.Sprintf("#!/bin/sh\necho \"$@\" > %s\nwhile [ $# -gt 0 ]; do [ \"$1\" = -oX ] && out=$2; shift; done\n%s\n",
		argsFile, body)
	path = filepath.Join(dir, "nmap")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, argsFile
}

// services: addresses in order, ports merged; only open TCP ports with a service count; IPv6 targets get -6.
func TestServices(t *testing.T) {
	nmap, argsFile := fakeNmap(t, `cat > "$out" <<EOF
<nmaprun>
<host><ports><port protocol="tcp" portid="1"><state state="open"/><service name="x"/></port></ports></host>
<host><address addr="192.0.2.1"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" version="9.6"/></port>
<port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
<port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>
<port protocol="tcp" portid="81"><state state="open"/></port>
</ports></host>
</nmaprun>
EOF`)
	xmlPath := filepath.Join(t.TempDir(), "n.xml")
	open := map[netip.Addr][]int{netip.MustParseAddr("192.0.2.2"): {80, 8080}, netip.MustParseAddr("192.0.2.1"): {22, 80}}
	got, err := services(context.Background(), nmap, xmlPath, "T4", open)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]map[int]service{"192.0.2.1": {22: {"ssh", "9.6"}}}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	args, _ := os.ReadFile(argsFile)
	if want := "-sT -sV -Pn --open -T4 -p 22,80,8080 -oX " + xmlPath + " -- 192.0.2.1 192.0.2.2"; strings.TrimSpace(string(args)) != want {
		t.Errorf("args %s, want %s", args, want)
	}

	if _, err := services(context.Background(), nmap, xmlPath, "T3",
		map[netip.Addr][]int{netip.MustParseAddr("2001:db8::1"): {443}}); err != nil {
		t.Fatal(err)
	}
	args, _ = os.ReadFile(argsFile)
	if !strings.HasSuffix(strings.TrimSpace(string(args)), "-6 -- 2001:db8::1") {
		t.Errorf("IPv6 args %s", args)
	}
}

func TestServicesFailures(t *testing.T) {
	one := map[netip.Addr][]int{netip.MustParseAddr("192.0.2.1"): {22}}
	long := strings.Repeat("e", 400)
	for _, c := range []struct {
		name, body, want string
	}{
		{"exit", "echo " + long + "TAIL >&2; exit 1", "exit status 1: " + long[:296] + "TAIL"},
		{"no-xml", "true", "no such file or directory"},
		{"bad-xml", `printf '<nmaprun><host>' > "$out"`, "XML syntax error"},
	} {
		t.Run(c.name, func(t *testing.T) {
			nmap, _ := fakeNmap(t, c.body)
			got, err := services(context.Background(), nmap, filepath.Join(t.TempDir(), "n.xml"), "T3", one)
			if err == nil || got != nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v, %v; want %q", got, err, c.want)
			}
		})
	}
}

func TestRunExternalErrors(t *testing.T) {
	t.Run("rundir", func(t *testing.T) {
		ctx, _ := ctxFor(t, org("192.0.2.1"))
		ctx.RunDir = filepath.Join(ctx.RunDir, "file")
		if err := os.WriteFile(ctx.RunDir, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if f, err := RunExternal(ctx, map[string]any{}, "production"); err == nil || f != nil {
			t.Errorf("got %v, %v", f, err)
		}
	})
	t.Run("ports", func(t *testing.T) {
		ctx, _ := ctxFor(t, org("192.0.2.1"))
		if _, err := RunExternal(ctx, map[string]any{"ports": "ssh"}, "production"); err == nil ||
			!strings.Contains(err.Error(), `bad port "ssh"`) {
			t.Errorf("err %v", err)
		}
	})
	t.Run("timing", func(t *testing.T) {
		ctx, logs := ctxFor(t, org("192.0.2.1"))
		f, err := RunExternal(ctx, map[string]any{"timing": "T9"}, "production")
		if err != nil || f != nil || !slices.Equal(*logs, []string{`external: unknown timing "T9"`}) {
			t.Errorf("got %v, %v, logs %q", f, err, *logs)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, _ := ctxFor(t, org("127.0.0.1"))
		cctx, cancel := context.WithCancel(context.Background())
		cancel()
		ctx.Context = cctx
		if f, err := RunExternal(ctx, map[string]any{"ports": "1"}, "production"); !errors.Is(err, context.Canceled) || f != nil {
			t.Errorf("got %v, %v", f, err)
		}
	})
}

// A target that doesn't resolve and an nmap that fails are logged; the open ports stay, without services.
func TestRunExternalLoggedFailures(t *testing.T) {
	open, _ := local(t, 1)
	nmap, _ := fakeNmap(t, "echo 'nmap: broken' >&2; exit 2")
	oldN, oldR := LookNmap, Resolver
	defer func() { LookNmap, Resolver = oldN, oldR }()
	LookNmap = func() (string, error) { return nmap, nil }
	Resolver = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	ctx, logs := ctxFor(t, org("127.0.0.1", "web-01.example.com"))
	f, err := RunExternal(ctx, map[string]any{"ports": open[0]}, "production")
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || f[0].Pkg != "" || f[0].Title != fmt.Sprintf("open %d/tcp", open[0]) {
		t.Errorf("findings %+v", f)
	}
	want := []string{"external 127.0.0.1: nmap failed: exit status 2: nmap: broken", "external 127.0.0.1: done",
		"external web-01.example.com: no such host"}
	if !slices.Equal(*logs, want) {
		t.Errorf("logs %q\nwant %q", *logs, want)
	}
}

// TestAddressesUnmapped: a name resolved to an IPv4-mapped address comes back as plain IPv4 (findings and nmap's
// command line show 192.0.2.7, not ::ffff:192.0.2.7).
func TestAddressesUnmapped(t *testing.T) {
	old := Resolver
	t.Cleanup(func() { Resolver = old })
	Resolver = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.7")}, nil
	}
	got, err := Addresses(context.Background(), "web.example.org")
	if err != nil || len(got) != 1 || got[0].String() != "192.0.2.7" || !got[0].Is4() {
		t.Fatalf("%v %v", got, err)
	}
}
