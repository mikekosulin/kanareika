// Package pyfmt reproduces the Python semantics kanareika's output depends on. Output files and texts keep exactly
// the format the earlier (Python) version wrote, so reports, test goldens and the dashboard stay byte-compatible
// across versions and with runs written before the port.
//
//   - text.go: str.split/strip/splitlines, int(), float(), round(), Unicode-aware regex classes, Counter — how the
//     checks parse command output.
//   - json.go: ordered objects (Obj, Ordered) and Python's json.dumps / json.loads / bool() on dynamic values, with
//     Python's float repr — the per-host module files.
//   - marshal.go: encoding/json output (struct-driven, Go number formatting) with json.dumps' separators and
//     escaping — run files, API and MCP responses.
package pyfmt
