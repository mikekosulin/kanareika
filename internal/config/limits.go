package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Defaults of the scan limits: SSH waits on the hosts, so many collect at once; each trivy match holds its report in
// memory, so few run at once.
const (
	DefaultParallel      = 8
	DefaultTrivyParallel = 2
	MaxParallel          = 64
)

// Limit: a scan limit and where its value comes from: "default", "settings" (policy/settings.yml, scan:), "org"
// (the org file, access.parallel) or "flag".
type Limit struct {
	Value  int    `json:"value"`
	Source string `json:"source"`
}

// Limits of a scan: Parallel hosts collected at once (SSH), TrivyParallel trivy matches at once (memory).
type Limits struct {
	Parallel      Limit `json:"parallel"`
	TrivyParallel Limit `json:"trivy_parallel"`
}

// ScanLimits: the limits for scanning o (nil: no org), from the built-in defaults, policy/settings.yml and the org
// file, the later winning; flags are applied by the caller (Limit.Override).
func ScanLimits(p Paths, o *Org) Limits {
	l := Limits{Limit{DefaultParallel, "default"}, Limit{DefaultTrivyParallel, "default"}}
	// the user's file only: the built-in one holds the defaults themselves
	if b, err := os.ReadFile(filepath.Join(p.Policy, "settings.yml")); err == nil {
		if v, err := YAML(b); err == nil {
			root, _ := v.(map[string]any)
			s := mapOf(root["scan"])
			if n, ok := limitOf(s["parallel"]); ok {
				l.Parallel = Limit{n, "settings"}
			}
			if n, ok := limitOf(s["trivy_parallel"]); ok {
				l.TrivyParallel = Limit{n, "settings"}
			}
		}
	}
	if o != nil {
		if n, ok := limitOf(o.Access()["parallel"]); ok {
			l.Parallel = Limit{n, "org"}
		}
	}
	return l
}

// Override: the limit set by a flag when n > 0.
func (l Limit) Override(n int) Limit {
	if n > 0 {
		return Limit{min(n, MaxParallel), "flag"}
	}
	return l
}

func limitOf(v any) (int, bool) {
	f, ok := v.(float64)
	if !ok || f < 1 || f != float64(int(f)) {
		return 0, false
	}
	return min(int(f), MaxParallel), true
}

// SetScanLimits writes scan.parallel and scan.trivy_parallel to policy/settings.yml (nil: unchanged; 0: removed,
// back to the default), keeping the rest of the file and its comments; a missing file starts from the built-in one.
func SetScanLimits(p Paths, parallel, trivyParallel *int) error {
	for _, n := range []*int{parallel, trivyParallel} {
		if n != nil && (*n < 0 || *n > MaxParallel) {
			return fmt.Errorf("scan limits are 1..%d (0 = default)", MaxParallel)
		}
	}
	b, err := Policy(p, "settings.yml")
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("policy/settings.yml: %w", err)
	}
	if len(doc.Content) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return errors.New("policy/settings.yml: not a mapping")
	}
	scan := child(root, "scan")
	if scan == nil {
		scan = &yaml.Node{Kind: yaml.MappingNode}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "scan",
			HeadComment: "Scan limits: hosts collected at once over SSH, trivy matches at once (each holds its report in memory)."},
			scan)
	}
	for key, n := range map[string]*int{"parallel": parallel, "trivy_parallel": trivyParallel} {
		if n == nil {
			continue
		}
		if *n == 0 {
			drop(scan, key)
			continue
		}
		if v := child(scan, key); v != nil {
			v.Kind, v.Tag, v.Value = yaml.ScalarNode, "!!int", strconv.Itoa(*n)
		} else {
			scan.Content = append(scan.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(*n)})
		}
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	if err := os.MkdirAll(p.Policy, 0o755); err != nil {
		return err
	}
	path := filepath.Join(p.Policy, "settings.yml")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func child(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func drop(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}
