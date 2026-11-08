package ospkg

import (
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/sbom"
	"github.com/mikekosulin/kanareika/internal/tree"
	"github.com/mikekosulin/kanareika/internal/trivy"
	"github.com/mikekosulin/kanareika/internal/vendor"
)

// An Ubuntu 22.04 host as trivy reports it: most "no fix" findings are CVEs Ubuntu has not fixed at all (status
// affected: needed / pending in the Ubuntu tracker), repeated for every binary package of one source (systemd,
// libsystemd0, libudev1, udev); some the vendor deferred or will not fix; some fixed only in an ESM build that a
// host without Ubuntu Pro cannot install; and one package has CVEs fixed in several builds.
const ubuntuReport = `{"SchemaVersion": 2, "ArtifactName": "sbom.cdx.json", "ArtifactType": "cyclonedx",
 "Metadata": {"OS": {"Family": "ubuntu", "Name": "22.04"}},
 "Results": [{"Target": "sbom.cdx.json (ubuntu 22.04)", "Class": "os-pkgs", "Type": "ubuntu", "Vulnerabilities": [
  {"VulnerabilityID": "CVE-2023-7008", "PkgName": "systemd", "InstalledVersion": "249.11-0ubuntu3.12", "Status": "affected", "Severity": "MEDIUM"},
  {"VulnerabilityID": "CVE-2023-7008", "PkgName": "libsystemd0", "InstalledVersion": "249.11-0ubuntu3.12", "Status": "affected", "Severity": "MEDIUM"},
  {"VulnerabilityID": "CVE-2023-7008", "PkgName": "libudev1", "InstalledVersion": "249.11-0ubuntu3.12", "Status": "affected", "Severity": "MEDIUM"},
  {"VulnerabilityID": "CVE-2023-7008", "PkgName": "udev", "InstalledVersion": "249.11-0ubuntu3.12", "Status": "affected", "Severity": "MEDIUM"},
  {"VulnerabilityID": "CVE-2023-26604", "PkgName": "systemd", "InstalledVersion": "249.11-0ubuntu3.12", "Status": "affected", "Severity": "LOW"},
  {"VulnerabilityID": "CVE-2022-3219", "PkgName": "gpgv", "InstalledVersion": "2.2.27-3ubuntu2.1", "Status": "fix_deferred", "Severity": "LOW"},
  {"VulnerabilityID": "CVE-2022-3219", "PkgName": "gnupg", "InstalledVersion": "2.2.27-3ubuntu2.1", "Status": "fix_deferred", "Severity": "LOW"},
  {"VulnerabilityID": "CVE-2016-2781", "PkgName": "coreutils", "InstalledVersion": "8.32-4.1ubuntu1.2", "Status": "will_not_fix", "Severity": "LOW"},
  {"VulnerabilityID": "CVE-2024-6387", "PkgName": "libtiff5", "InstalledVersion": "4.3.0-6ubuntu0.8", "FixedVersion": "4.3.0-6ubuntu0.9+esm1", "Status": "fixed", "Severity": "MEDIUM"},
  {"VulnerabilityID": "CVE-2024-2511", "PkgName": "libssl3", "InstalledVersion": "3.0.2-0ubuntu1.15", "FixedVersion": "3.0.2-0ubuntu1.16", "Status": "fixed", "Severity": "LOW"},
  {"VulnerabilityID": "CVE-2024-5535", "PkgName": "libssl3", "InstalledVersion": "3.0.2-0ubuntu1.15", "FixedVersion": "3.0.2-0ubuntu1.18", "Status": "fixed", "Severity": "LOW"},
  {"VulnerabilityID": "CVE-2024-2511", "PkgName": "openssl", "InstalledVersion": "3.0.2-0ubuntu1.15", "FixedVersion": "3.0.2-0ubuntu1.16", "Status": "fixed", "Severity": "LOW"},
  {"VulnerabilityID": "CVE-2024-5535", "PkgName": "openssl", "InstalledVersion": "3.0.2-0ubuntu1.15", "FixedVersion": "3.0.2-0ubuntu1.18", "Status": "fixed", "Severity": "LOW"}
 ]}]}`

const ubuntuPackages = "ii \tsystemd\t249.11-0ubuntu3.12\tamd64\tsystemd\t249.11-0ubuntu3.12\n" +
	"ii \tlibsystemd0\t249.11-0ubuntu3.12\tamd64\tsystemd\t249.11-0ubuntu3.12\n" +
	"ii \tlibudev1\t249.11-0ubuntu3.12\tamd64\tsystemd\t249.11-0ubuntu3.12\n" +
	"ii \tudev\t249.11-0ubuntu3.12\tamd64\tsystemd\t249.11-0ubuntu3.12\n" +
	"ii \tgpgv\t2.2.27-3ubuntu2.1\tamd64\tgnupg2\t2.2.27-3ubuntu2.1\n" +
	"ii \tgnupg\t2.2.27-3ubuntu2.1\tall\tgnupg2\t2.2.27-3ubuntu2.1\n" +
	"ii \tcoreutils\t8.32-4.1ubuntu1.2\tamd64\tcoreutils\t8.32-4.1ubuntu1.2\n" +
	"ii \tlibtiff5\t4.3.0-6ubuntu0.8\tamd64\ttiff\t4.3.0-6ubuntu0.8\n" +
	"ii \tlibssl3\t3.0.2-0ubuntu1.15\tamd64\topenssl\t3.0.2-0ubuntu1.15\n" +
	"ii \topenssl\t3.0.2-0ubuntu1.15\tamd64\topenssl\t3.0.2-0ubuntu1.15\n"

// apt without Ubuntu Pro offers the openssl update, not the ESM build of tiff
const ubuntuUpgrades = "Listing...\n" +
	"libssl3/jammy-updates,jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.15]\n" +
	"openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.15]\n@@rc 0\n"

func TestNoFixOnUbuntu(t *testing.T) {
	r, err := trivy.ParseReport([]byte(ubuntuReport))
	if err != nil {
		t.Fatal(err)
	}
	base := finding.Finding{Org: "acme", Host: "nas", Group: "home", Module: "os_packages", Target: "os"}
	fs := trivy.VulnFindings(r, base)
	SetSources(fs, sbom.ParsePackages("deb", ubuntuPackages))
	vendor.Annotate(fs, nil, vendor.ParseUpgrades("deb", ubuntuUpgrades), "")
	p := "P3"
	for i := range fs {
		fs[i].Priority = &p
	}
	why := map[string]string{}
	for _, f := range fs {
		why[f.Pkg+" "+f.ID] = f.NoFix()
	}
	for k, want := range map[string]string{
		"udev CVE-2023-7008": finding.NoFixPending, "gnupg CVE-2022-3219": finding.NoFixDeferred,
		"coreutils CVE-2016-2781": finding.NoFixWontFix, "libtiff5 CVE-2024-6387": finding.NoFixESM,
		"libssl3 CVE-2024-2511": "",
	} {
		if why[k] != want {
			t.Errorf("%s: %q, want %q", k, why[k], want)
		}
	}
	if fs[1].SrcPkg != "systemd" || fs[0].SrcPkg != "" {
		t.Errorf("sources: %q %q", fs[0].SrcPkg, fs[1].SrcPkg)
	}

	// 13 rows; one openssl update (two binaries, two builds with fixes: the newest is the target), and four things
	// with nothing to install: systemd (4 binaries, 2 CVEs), gnupg2 (2 binaries), coreutils, tiff (ESM only)
	tot := report.TotalsOf(fs)
	if tot.Findings != 13 || tot.Fixes != 5 || tot.NoFix != 4 || tot.CVEs != 7 {
		t.Fatalf("%+v", tot)
	}
	tr := tree.Build(fs, tree.Hosts{}, tree.Opts{})
	if tr.Fixes != tot.Fixes || tr.NoFix != tot.NoFix || len(tr.Nodes) != tot.Fixes {
		t.Fatalf("tree %d fixes / %d no fix / %d rows, totals %+v", tr.Fixes, tr.NoFix, len(tr.Nodes), tot)
	}
	byLabel := map[string]*tree.Node{}
	for _, n := range tr.Nodes {
		byLabel[n.Label] = n
	}
	if o := byLabel["openssl"]; o == nil || o.Fixed != "3.0.2-0ubuntu1.18" || len(o.Pkgs) != 2 || o.States["available"] != 1 {
		t.Errorf("openssl: %+v", o)
	}
	if s := byLabel["systemd"]; s == nil || len(s.Pkgs) != 4 || s.CVEs != 2 || s.NoFix[finding.NoFixPending] != 1 {
		t.Errorf("systemd: %+v", s)
	}
	if n := byLabel["libtiff5"]; n == nil || n.NoFix[finding.NoFixESM] != 1 {
		t.Errorf("tiff: %+v", n)
	}
	if n := byLabel["gnupg2"]; n == nil || n.NoFix[finding.NoFixDeferred] != 1 {
		t.Errorf("gnupg2: %+v", n)
	}
	if n := byLabel["coreutils"]; n == nil || n.NoFix[finding.NoFixWontFix] != 1 {
		t.Errorf("coreutils: %+v", n)
	}
	d := tree.Describe(byLabel["openssl"], tree.Hosts{"nas": {OS: ptr("Ubuntu 22.04.5 LTS")}}, nil, "2026-11-09")
	if len(d.Apply) != 1 || d.Apply[0].Command != "apt-get update && apt-get install --only-upgrade libssl3 openssl" {
		t.Errorf("apply: %+v", d.Apply)
	}
}

func ptr(s string) *string { return &s }
