package check

import (
	"reflect"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
)

var host = config.Host{Org: "acme", Name: "web-01", Group: "web", Exposure: 2, Address: "192.0.2.10"}

func TestBase(t *testing.T) {
	got := Base(host, "access")
	want := finding.Finding{Org: "acme", Host: "web-01", Group: "web", Exposure: 2, Module: "access"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestNew(t *testing.T) {
	title := i18n.Text{Text: "Disk almost full", Key: "health.disk", Args: map[string]any{"pct": 95}}
	detail := i18n.Text{Text: "/var: 95% used", Key: "health.disk.detail", Args: map[string]any{"mount": "/var"}}
	f := New(host, "health", finding.Health, "disk", "HIGH", title, detail, 0)
	if f.Kind != finding.Health || f.ID != "disk" || f.Severity != "HIGH" || f.Module != "health" || f.Host != "web-01" {
		t.Errorf("where/what: %+v", f)
	}
	if f.Title != "Disk almost full" || f.Msg != "health.disk" || !reflect.DeepEqual(f.Args, title.Args) {
		t.Errorf("title: %q %q %v", f.Title, f.Msg, f.Args)
	}
	if f.Target != "/var: 95% used" || f.TargetMsg != "health.disk.detail" || !reflect.DeepEqual(f.TargetArgs, detail.Args) {
		t.Errorf("detail: %q %q %v", f.Target, f.TargetMsg, f.TargetArgs)
	}
}

func TestNewTruncatesByRunes(t *testing.T) {
	f := New(host, "m", finding.Misconfig, "id", "LOW", i18n.Text{Text: "t"}, i18n.Text{Text: "привет мир"}, 6)
	if f.Target != "привет" {
		t.Errorf("target %q, want the first 6 runes", f.Target)
	}
	if f.TargetMsg != "" || f.TargetArgs != nil {
		t.Errorf("plain detail got a message: %q %v", f.TargetMsg, f.TargetArgs)
	}
	// short enough: unchanged
	if f := New(host, "m", finding.Misconfig, "id", "LOW", i18n.Text{Text: "t"}, i18n.Text{Text: "abc"}, 6); f.Target != "abc" {
		t.Errorf("target %q", f.Target)
	}
}

func TestNewPlainTitleDropsArgs(t *testing.T) {
	f := New(host, "m", finding.Exposure, "id", "LOW", i18n.Text{Text: "plain", Args: map[string]any{"x": 1}},
		i18n.Text{}, 0)
	if f.Title != "plain" || f.Msg != "" || f.Args != nil {
		t.Errorf("title %q msg %q args %v", f.Title, f.Msg, f.Args)
	}
}

func TestMisconfig(t *testing.T) {
	long := "0123456789012345678901234567890123456789"
	f := Misconfig(host, "access", "ssh.root", "HIGH", i18n.Text{Text: "Root login", Key: "ssh.root"}, i18n.Text{Text: long})
	if f.Kind != finding.Misconfig || f.ID != "ssh.root" || f.Severity != "HIGH" || f.Target != long || f.Msg != "ssh.root" {
		t.Errorf("%+v", f)
	}
}
