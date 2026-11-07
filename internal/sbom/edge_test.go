package sbom

import (
	"reflect"
	"testing"
)

// An apk entry without an origin line ("o:") is its own source package.
func TestApkWithoutOrigin(t *testing.T) {
	apk := "P:musl\nV:1.2.4-r2\nA:x86_64\no:musl\n\nP:busybox-extras\nV:1.36.1-r5\nA:x86_64\n"
	got := ParsePackages("apk", apk)
	want := []Package{
		{Name: "musl", Version: "1.2.4-r2", Arch: "x86_64", SrcName: "musl", SrcVersion: "1.2.4-r2"},
		{Name: "busybox-extras", Version: "1.36.1-r5", Arch: "x86_64", SrcName: "busybox-extras", SrcVersion: "1.36.1-r5"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("apk:\n%+v\nwant\n%+v", got, want)
	}
}

// Without PRETTY_NAME the error names the OS by its ID.
func TestUnsupportedOSByID(t *testing.T) {
	_, err := BuildCycloneDX("web-01", map[string]string{"ID": "acmeos", "VERSION_ID": "1"}, nil)
	if err == nil || err.Error() != "unsupported OS: acmeos" {
		t.Fatalf("err = %v", err)
	}
}
