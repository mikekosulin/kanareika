package sbom

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestDebAndRpmParsing(t *testing.T) {
	deb := "ii \tlibssl3\t3.0.15-1~deb12u1\tamd64\topenssl\t3.0.15-1~deb12u1\nrc \told\t1\tamd64\told\t1\n"
	p := ParsePackages("deb", deb)
	if len(p) != 1 || p[0].SrcName != "openssl" || p[0].Release != "1~deb12u1" {
		t.Fatalf("deb: %+v", p)
	}
	rpm := "openssl-libs\t1\t3.0.7\t27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm\ngpg-pubkey\t(none)\t1\t2\t(none)\t(none)\n"
	p = ParsePackages("rpm", rpm)
	if len(p) != 1 || p[0].Epoch != "1" || p[0].SrcName != "openssl" {
		t.Fatalf("rpm: %+v", p)
	}
	bom, err := BuildCycloneDX("h", map[string]string{"ID": "rocky", "VERSION_ID": "9.3"}, p)
	if err != nil || !strings.Contains(bom.Components[1].Purl, "epoch=1") {
		t.Fatalf("bom: %v %+v", err, bom)
	}
	if _, err := BuildCycloneDX("h", map[string]string{"ID": "linuxmint", "PRETTY_NAME": "Mint 22"}, p); err == nil ||
		err.Error() != "unsupported OS: Mint 22" {
		t.Fatal(err)
	}
}

func TestOldRedhatRelease(t *testing.T) {
	got := OSReleaseFromRedhat("CentOS release 6.10 (Final)\n")
	want := map[string]string{"ID": "centos", "VERSION_ID": "6", "PRETTY_NAME": "CentOS release 6.10 (Final)"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	if got := OSReleaseFromRedhat(""); len(got) != 0 {
		t.Fatal(got)
	}
}

// testdata/python.json: recorded with the former Python implementation over real package lists (packages-*.txt from
// scanned hosts, anonymized) and edge cases. Recorded once with the former Python implementation (removed from the
// repo; the Go port had to match it) and kept as a frozen fixture: a change here is a behaviour change — review it
// as such.
type golden struct {
	Cases map[string]struct {
		Ptype     string            `json:"ptype"`
		OSRelease map[string]string `json:"os_release"`
		Family    []string          `json:"family"`
		Packages  []Package         `json:"packages"`
		BOM       any               `json:"bom"`
	} `json:"cases"`
	RedhatRelease [][2]json.RawMessage `json:"redhat_release"`
	OSRelease     [][3]json.RawMessage `json:"os_release"`
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

func read(t *testing.T, name string) string {
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func familySlice(f Family, ok bool) []string {
	if !ok {
		return nil
	}
	return []string{f.OS, f.Type, f.Namespace}
}

func TestMatchesPython(t *testing.T) {
	g := load(t)
	osName := map[string]string{"edge": "ubuntu", "rpm-edge": "centos9"}
	for name, c := range g.Cases {
		osn := osName[name]
		if osn == "" {
			osn = name
		}
		osr := ParseOSRelease(read(t, "os-release-"+osn+".txt"))
		if !reflect.DeepEqual(osr, c.OSRelease) {
			t.Errorf("%s: os-release %v, want %v", name, osr, c.OSRelease)
		}
		if f := familySlice(FamilyFor(osr)); !reflect.DeepEqual(f, c.Family) {
			t.Errorf("%s: family %v, want %v", name, f, c.Family)
		}
		pkgs := ParsePackages(c.Ptype, read(t, "packages-"+name+".txt"))
		if !reflect.DeepEqual(pkgs, c.Packages) {
			for i := range min(len(pkgs), len(c.Packages)) {
				if pkgs[i] != c.Packages[i] {
					t.Errorf("%s: package %d: %+v, want %+v", name, i, pkgs[i], c.Packages[i])
					break
				}
			}
			t.Fatalf("%s: %d packages, want %d", name, len(pkgs), len(c.Packages))
		}
		bom, err := BuildCycloneDX("host-"+name, osr, pkgs)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(bom)
		s := strings.NewReplacer(bom.Metadata.Component.BOMRef, "HOST-REF", bom.Components[0].BOMRef, "OS-REF",
			bom.SerialNumber, "urn:uuid:SERIAL").Replace(string(b))
		var got any
		if err := json.Unmarshal([]byte(s), &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, c.BOM) {
			t.Errorf("%s: bom differs", name)
		}
	}
	for _, c := range g.RedhatRelease {
		var text string
		var want map[string]string
		_ = json.Unmarshal(c[0], &text)
		_ = json.Unmarshal(c[1], &want)
		if got := OSReleaseFromRedhat(text); !reflect.DeepEqual(got, want) {
			t.Errorf("redhat-release %q: %v, want %v", text, got, want)
		}
	}
	for _, c := range g.OSRelease {
		var text string
		var want map[string]string
		var fam []string
		_ = json.Unmarshal(c[0], &text)
		_ = json.Unmarshal(c[1], &want)
		_ = json.Unmarshal(c[2], &fam)
		got := ParseOSRelease(text)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("os-release %q: %v, want %v", text, got, want)
		}
		if f := familySlice(FamilyFor(got)); !reflect.DeepEqual(f, fam) {
			t.Errorf("os-release %q: family %v, want %v", text, f, fam)
		}
	}
}

func TestUUID(t *testing.T) {
	u := newUUID()
	if len(u) != 36 || u[14] != '4' || strings.IndexByte("89ab", u[19]) < 0 {
		t.Fatal(u)
	}
}
