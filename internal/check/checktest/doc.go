// Package checktest: test helpers for the check modules. They replay command outputs recorded on real hosts
// against a module (a fake check.Runner and trivy) and compare its findings, written files, log and commands with
// frozen goldens recorded from the former Python implementation (no longer in the repo); a difference there is a
// behaviour change. Two fixture layouts: case directories (golden.go) and testdata/python.json (replay.go).
// Only tests import it.
package checktest
