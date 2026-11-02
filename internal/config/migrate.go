package config

import (
	"bytes"
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// CurrentVersion of the org file format. A file without `version` is version 1.
//
// Changing the format = bump CurrentVersion and append a migration that turns version N-1 into N. Migrations edit
// the YAML node tree, so comments and key order survive `kanareika migrate`. Old files keep working: Load migrates
// them in memory before validation.
const CurrentVersion = 1

type migration struct {
	to    int    // the version the file has after this step
	about string // what changed, shown by `kanareika migrate`
	apply func(root *yaml.Node) error
}

// migrations, in order; migrations[i].to == i+2.
var migrations []migration

// FileVersion of a parsed document (1 when absent).
func FileVersion(root *yaml.Node) (int, error) {
	n := lookup(root, "version")
	if n == nil {
		return 1, nil
	}
	v, err := strconv.Atoi(n.Value)
	if err != nil || v < 1 {
		return 0, fmt.Errorf("version: %q is not a positive integer", n.Value)
	}
	return v, nil
}

// Migrate brings the document to CurrentVersion; returns the steps applied.
func Migrate(doc *yaml.Node) ([]string, error) {
	root := docRoot(doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, nil
	}
	v, err := FileVersion(root)
	if err != nil {
		return nil, err
	}
	if v > CurrentVersion {
		return nil, fmt.Errorf("format version %d is newer than this kanareika understands (%d): update kanareika", v, CurrentVersion)
	}
	var done []string
	for _, m := range migrations {
		if m.to <= v {
			continue
		}
		if err := m.apply(root); err != nil {
			return done, fmt.Errorf("migration to version %d: %w", m.to, err)
		}
		done = append(done, fmt.Sprintf("v%d: %s", m.to, m.about))
		v = m.to
	}
	if len(done) > 0 {
		setScalar(root, "version", strconv.Itoa(v))
	}
	return done, nil
}

// MigrateFile rewrites one org file in the current format (keeping a .bak copy). dryRun: report only.
func MigrateFile(path string, dryRun bool) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	steps, err := Migrate(&doc)
	if err != nil || len(steps) == 0 || dryRun {
		return steps, err
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path+".bak", b, 0o600); err != nil {
		return nil, err
	}
	return steps, os.WriteFile(path, out.Bytes(), 0o600)
}

// --- yaml.Node helpers (for migrations) ---------------------------------------------------------------------

func docRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return nil
		}
		return doc.Content[0]
	}
	return doc
}

// lookup the value node of key in a mapping node.
func lookup(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// setScalar sets key to a scalar value; a new key goes first (version heads the file).
func setScalar(m *yaml.Node, key, value string) {
	if n := lookup(m, key); n != nil {
		n.Kind, n.Tag, n.Value = yaml.ScalarNode, "!!int", value
		return
	}
	k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	v := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: value}
	m.Content = append([]*yaml.Node{k, v}, m.Content...)
}

// renameKey renames a key of a mapping, keeping its place and comments. For migrations.
func renameKey(m *yaml.Node, from, to string) bool {
	if m == nil || m.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == from {
			m.Content[i].Value = to
			return true
		}
	}
	return false
}

// deleteKey removes a key from a mapping. For migrations.
func deleteKey(m *yaml.Node, key string) bool {
	if m == nil || m.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return true
		}
	}
	return false
}
