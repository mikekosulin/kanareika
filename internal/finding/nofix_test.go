package finding

import "testing"

func TestNoFix(t *testing.T) {
	cases := []struct {
		name string
		f    Finding
		want string
	}{
		{"misconfig", Finding{Kind: "misconfig"}, ""},
		{"no fix yet", Finding{Kind: Vuln, Status: "affected"}, NoFixPending},
		{"will not fix", Finding{Kind: Vuln, Status: "will_not_fix"}, NoFixWontFix},
		{"end of life", Finding{Kind: Vuln, Status: "end_of_life"}, NoFixWontFix},
		{"deferred", Finding{Kind: Vuln, Status: "fix_deferred"}, NoFixDeferred},
		{"in repos", Finding{Kind: Vuln, Fixed: "1.2", FixState: FixAvailable}, ""},
		{"reboot", Finding{Kind: Vuln, Fixed: "1.2", FixState: FixReboot}, ""},
		{"not in repos", Finding{Kind: Vuln, Fixed: "1.2", FixState: FixVendor}, NoFixRepos},
		{"esm, repos asked", Finding{Kind: Vuln, Fixed: "1.2-3ubuntu0.1+esm1", FixState: FixVendor}, NoFixESM},
		{"esm, repos not asked", Finding{Kind: Vuln, Fixed: "2.0~esm2", Target: "os"}, NoFixESM},
		{"esm in an image", Finding{Kind: Vuln, Fixed: "2.0~esm2", Target: "image:x"}, ""},
		{"fix, repos not asked", Finding{Kind: Vuln, Fixed: "1.2", Target: "os"}, ""},
	}
	for _, c := range cases {
		if got := c.f.NoFix(); got != c.want {
			t.Errorf("%s: NoFix() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestIsESMAndSource(t *testing.T) {
	for v, want := range map[string]bool{"1.2-3ubuntu0.1+esm1": true, "2.0~esm2": true, "1.2-3ubuntu0.1": false, "": false} {
		if IsESM(v) != want {
			t.Errorf("IsESM(%q) = %v", v, !want)
		}
	}
	if s := (&Finding{Pkg: "libssl3", SrcPkg: "openssl"}).Source(); s != "openssl" {
		t.Errorf("source %q", s)
	}
	if s := (&Finding{Pkg: "bash"}).Source(); s != "bash" {
		t.Errorf("no source package: %q", s)
	}
}
