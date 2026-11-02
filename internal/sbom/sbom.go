// Package sbom turns a remote host's package list into a CycloneDX SBOM that `trivy sbom` understands.
//
// The host only runs read-only queries (dpkg-query / rpm -qa / cat apk db); vulnerability matching happens on the
// scanner side.
package sbom

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strings"

	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

// Family of an os-release ID: trivy OS family, purl type (= package type), purl namespace.
type Family struct {
	OS        string
	Type      string
	Namespace string
}

var Families = map[string]Family{
	"debian":    {"debian", "deb", "debian"},
	"ubuntu":    {"ubuntu", "deb", "ubuntu"},
	"rhel":      {"redhat", "rpm", "redhat"},
	"centos":    {"centos", "rpm", "centos"},
	"rocky":     {"rocky", "rpm", "rocky"},
	"almalinux": {"alma", "rpm", "alma"},
	"ol":        {"oracle", "rpm", "oracle"},
	"amzn":      {"amazon", "rpm", "amazon"},
	"alpine":    {"alpine", "apk", "alpine"},
}

// PkgQuery: the read-only command that lists installed packages, per package type.
var PkgQuery = map[string]string{
	"deb": `dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n'`,
	"rpm": `rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n'`,
	"apk": "cat /lib/apk/db/installed",
}

// Package: one installed package, binary and source coordinates (epoch "" = none).
type Package struct {
	Name       string `json:"name"`
	Epoch      string `json:"epoch"`
	Version    string `json:"version"`
	Release    string `json:"release"`
	Arch       string `json:"arch"`
	SrcName    string `json:"src_name"`
	SrcEpoch   string `json:"src_epoch"`
	SrcVersion string `json:"src_version"`
	SrcRelease string `json:"src_release"`
}

func ParseOSRelease(text string) map[string]string {
	out := map[string]string{}
	for _, line := range pyfmt.SplitLines(text) {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.Trim(strings.TrimSpace(v), `"`), "'")
	}
	return out
}

var redhatRelease = regexp.MustCompile(`^(.+?) release (\d+)`)

// OSReleaseFromRedhat: "CentOS release 6.10 (Final)" -> os-release fields (major version, as the vendor advisories
// use). RHEL/CentOS 6 have no /etc/os-release.
func OSReleaseFromRedhat(text string) map[string]string {
	text = strings.TrimSpace(text)
	m := redhatRelease.FindStringSubmatch(text)
	if m == nil {
		return map[string]string{}
	}
	name := strings.ToLower(m[1])
	id := ""
	switch {
	case strings.Contains(name, "centos"):
		id = "centos"
	case strings.Contains(name, "red hat"):
		id = "rhel"
	case strings.Contains(name, "oracle"):
		id = "ol"
	}
	if id == "" {
		return map[string]string{"PRETTY_NAME": text}
	}
	return map[string]string{"ID": id, "VERSION_ID": m[2], "PRETTY_NAME": text}
}

// FamilyFor: no guessing via ID_LIKE — derivatives have their own advisories, a wrong family gives wrong results.
func FamilyFor(osRelease map[string]string) (Family, bool) {
	f, ok := Families[osRelease["ID"]]
	return f, ok
}

// splitDeb: "1:2.36-9+deb12u4" -> ("1", "2.36", "9+deb12u4").
func splitDeb(full string) (epoch, ver, rel string) {
	rest := full
	if e, r, ok := strings.Cut(full, ":"); ok {
		epoch, rest = e, r
	}
	if i := strings.LastIndex(rest, "-"); i >= 0 {
		return epoch, rest[:i], rest[i+1:]
	}
	return epoch, rest, ""
}

func ParsePackages(ptype, text string) []Package {
	var pkgs []Package
	switch ptype {
	case "deb":
		for _, line := range pyfmt.SplitLines(text) {
			parts := strings.Split(line, "\t")
			if len(parts) < 6 || !strings.HasPrefix(parts[0], "ii") {
				continue
			}
			name, version, arch, src, srcVersion := parts[1], parts[2], parts[3], parts[4], parts[5]
			if srcVersion == "" {
				srcVersion = version
			}
			if src == "" {
				src = name
			}
			e, v, r := splitDeb(version)
			se, sv, sr := splitDeb(srcVersion)
			pkgs = append(pkgs, Package{name, e, v, r, arch, src, se, sv, sr})
		}
	case "rpm":
		for _, line := range pyfmt.SplitLines(text) {
			parts := strings.Split(line, "\t")
			if len(parts) < 6 || parts[0] == "gpg-pubkey" {
				continue
			}
			name, epoch, ver, rel, arch, srpm := parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
			if epoch == "(none)" {
				epoch = ""
			}
			srcName, srcVer, srcRel := name, ver, rel
			if base, ok := strings.CutSuffix(srpm, ".src.rpm"); ok {
				// name-version-release; Python raises on a malformed name, here the binary coordinates stay
				if i := strings.LastIndex(base, "-"); i >= 0 {
					if j := strings.LastIndex(base[:i], "-"); j >= 0 {
						srcName, srcVer, srcRel = base[:j], base[j+1:i], base[i+1:]
					}
				}
			}
			pkgs = append(pkgs, Package{name, epoch, ver, rel, arch, srcName, epoch, srcVer, srcRel})
		}
	case "apk":
		cur := map[string]string{}
		flush := func() {
			if p := cur["P"]; p != "" {
				src, ok := cur["o"]
				if !ok {
					src = p
				}
				pkgs = append(pkgs, Package{Name: p, Version: cur["V"], Arch: cur["A"], SrcName: src,
					SrcVersion: cur["V"]})
			}
			cur = map[string]string{}
		}
		for _, line := range append(pyfmt.SplitLines(text), "") {
			r := []rune(line)
			switch {
			case strings.TrimSpace(line) == "":
				flush()
			case len(r) > 2 && r[1] == ':':
				cur[string(r[0])] = string(r[2:])
			}
		}
	}
	return pkgs
}

// quote is urllib.parse.quote (safe="/"): everything but letters, digits, "_.-~/" is percent-encoded as UTF-8.
func quote(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("_.-~/", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func fullVersion(p Package) string {
	if p.Release != "" {
		return p.Version + "-" + p.Release
	}
	return p.Version
}

func purl(ptype, ns string, p Package, distro string) string {
	var q []string
	if p.Arch != "" {
		q = append(q, "arch="+quote(p.Arch))
	}
	if p.Epoch != "" && p.Epoch != "0" {
		q = append(q, "epoch="+p.Epoch)
	}
	q = append(q, "distro="+quote(distro))
	return fmt.Sprintf("pkg:%s/%s/%s@%s?%s", ptype, ns, quote(p.Name), quote(fullVersion(p)), strings.Join(q, "&"))
}

// CycloneDX document, fields in the order the Python version wrote them.
type BOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies"`
}

type Metadata struct {
	Tools     Tools     `json:"tools"`
	Component Component `json:"component"`
}

type Tools struct {
	Components []Component `json:"components"`
}

type Component struct {
	BOMRef     string     `json:"bom-ref,omitempty"`
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Version    *string    `json:"version,omitempty"`
	Purl       string     `json:"purl,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

func BuildCycloneDX(hostname string, osRelease map[string]string, packages []Package) (*BOM, error) {
	fam, ok := FamilyFor(osRelease)
	if !ok {
		name := osRelease["PRETTY_NAME"]
		if name == "" {
			name = osRelease["ID"]
		}
		return nil, fmt.Errorf("unsupported OS: %s", name)
	}
	osVersion := osRelease["VERSION_ID"]
	distro := fam.OS + "-" + osVersion
	osRef, hostRef := newUUID(), newUUID()

	comps := []Component{{BOMRef: osRef, Type: "operating-system", Name: fam.OS, Version: &osVersion}}
	refs := make([]string, 0, len(packages))
	for _, p := range packages {
		ref := purl(fam.Type, fam.Namespace, p, distro)
		refs = append(refs, ref)
		props := []Property{
			{"aquasecurity:trivy:PkgType", fam.OS},
			{"aquasecurity:trivy:SrcName", p.SrcName},
			{"aquasecurity:trivy:SrcVersion", p.SrcVersion},
		}
		if p.SrcRelease != "" {
			props = append(props, Property{"aquasecurity:trivy:SrcRelease", p.SrcRelease})
		}
		if p.SrcEpoch != "" && p.SrcEpoch != "0" {
			props = append(props, Property{"aquasecurity:trivy:SrcEpoch", p.SrcEpoch})
		}
		version := fullVersion(p)
		if p.Epoch != "" && p.Epoch != "0" {
			version = p.Epoch + ":" + version
		}
		comps = append(comps, Component{BOMRef: ref, Type: "library", Name: p.Name, Version: &version, Purl: ref,
			Properties: props})
	}
	deps := []Dependency{{hostRef, []string{osRef}}, {osRef, refs}}
	for _, r := range refs {
		deps = append(deps, Dependency{r, []string{}})
	}
	return &BOM{
		BOMFormat: "CycloneDX", SpecVersion: "1.5", SerialNumber: "urn:uuid:" + newUUID(), Version: 1,
		Metadata: Metadata{
			Tools: Tools{Components: []Component{{Type: "application", Name: "kanareika"}}},
			Component: Component{BOMRef: hostRef, Type: "application", Name: hostname,
				Properties: []Property{{"aquasecurity:trivy:SchemaVersion", "2"}}},
		},
		Components:   comps,
		Dependencies: deps,
	}, nil
}

// newUUID: random (version 4) UUID.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
