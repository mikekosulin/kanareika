package tui

import "runtime"

// What the OS says, for assertions on error texts: Windows words the same errors differently.
var (
	errNotDir = map[bool]string{false: "not a directory", true: "cannot find the path"}[runtime.GOOS == "windows"]
	errIsDir  = map[bool]string{false: "is a directory", true: "Incorrect function"}[runtime.GOOS == "windows"]
	errNoFile = map[bool]string{false: "no such file", true: "cannot find the"}[runtime.GOOS == "windows"]
)

var _, _, _ = errNotDir, errIsDir, errNoFile
