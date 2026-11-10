package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/mikekosulin/kanareika/internal/trivy"
	"github.com/mikekosulin/kanareika/internal/trivy/engine"
	"github.com/mikekosulin/kanareika/internal/trivy/ocitest"
)

// TestMain: the test binary is kanareika's trivy too (`<test binary> __trivy ...`), as the real binary is.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == trivy.EngineCommand {
		os.Exit(engine.Main(os.Args[2:]))
	}
	os.Exit(m.Run())
}

// advisoryDB: a trivy-db holding one npm advisory (lodash < 4.17.12, CVE-2019-10744), laid out as trivy-db's
// fixtures are.
func advisoryDB(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trivy.db")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	src := "npm::GitHub Security Advisory Npm"
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(src))
		if err != nil {
			return err
		}
		pkg, err := b.CreateBucketIfNotExists([]byte("lodash"))
		if err != nil {
			return err
		}
		if err := pkg.Put([]byte("CVE-2019-10744"), []byte(`{"PatchedVersions":["4.17.12"],"VulnerableVersions":["< 4.17.12"]}`)); err != nil {
			return err
		}
		ds, err := tx.CreateBucketIfNotExists([]byte("data-source"))
		if err != nil {
			return err
		}
		if err := ds.Put([]byte(src), []byte(`{"ID":"ghsa","Name":"GitHub Security Advisory Npm","URL":"https://github.com/advisories"}`)); err != nil {
			return err
		}
		v, err := tx.CreateBucketIfNotExists([]byte("vulnerability"))
		if err != nil {
			return err
		}
		return v.Put([]byte("CVE-2019-10744"), []byte(`{"Title":"lodash: prototype pollution in defaultsDeep","Severity":"CRITICAL"}`))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestEmbeddedTrivyReadsDownloadedDB: kanareika downloads the DB layer itself (a local registry, no network) and
// the embedded trivy, run as scans run it (--skip-db-update), finds a vulnerability with it.
func TestEmbeddedTrivyReadsDownloadedDB(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("runs the embedded trivy")
	}
	t.Setenv("TRIVY_CACHE_DIR", filepath.Join(t.TempDir(), "trivy"))
	t.Setenv("KANAREIKA_TRIVY", "")
	t.Setenv("TRIVY_DB_REPOSITORY", "")
	reg := ocitest.New(t)
	now := time.Now().UTC()
	layer := ocitest.Layer(map[string][]byte{"trivy.db": advisoryDB(t),
		"metadata.json": ocitest.Metadata(2, now.Add(6*time.Hour), now.Add(-time.Hour))})
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", reg.Push("aquasecurity/trivy-db", "2",
		"application/vnd.aquasec.trivy.db.layer.v1.tar+gzip", layer))

	ctx := context.Background()
	if err := trivy.Prepare(ctx, t.Logf); err != nil {
		t.Fatal(err)
	}
	proj := t.TempDir()
	lock := `{"name":"app","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{"lodash":{"version":"4.17.11"}}}`
	if err := os.WriteFile(filepath.Join(proj, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := trivy.Run(ctx, []string{"fs", "--scanners", "vuln", "--offline-scan", proj}, filepath.Join(t.TempDir(), "out.json"), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(data)
	data.Close()
	if err != nil {
		t.Fatal(err)
	}
	r, err := trivy.ParseReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			found = found || v.VulnerabilityID == "CVE-2019-10744" && v.PkgName == "lodash" && v.FixedVersion == "4.17.12"
		}
	}
	if !found {
		t.Fatalf("trivy did not use the downloaded DB:\n%s", data)
	}
}
