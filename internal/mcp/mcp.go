// Package mcp is the MCP server over stdio (JSON-RPC 2.0, one message per line): read-only access to audit
// results for agents. Hand-written rather than an SDK so the wire output stays the same as the Python server's.
//
// Scans are deliberately NOT exposed: they connect to real servers, so starting one stays a human decision.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

// DefaultProtocol: answered when the client does not say which protocol version it speaks.
const DefaultProtocol = "2025-06-18"

type Server struct {
	store   *Store
	version string
	tools   map[string]func(args) (any, error)
	// Log gets protocol errors (stderr by default); stdout is the protocol channel.
	Log io.Writer
}

func NewServer(p config.Paths, version string) *Server {
	s := &Server{store: NewStore(p), version: version, Log: os.Stderr}
	s.tools = map[string]func(args) (any, error){
		"list_orgs": s.listOrgs, "get_summary": s.getSummary, "list_actions": s.listActions, "get_host": s.getHost,
		"search_packages": s.searchPackages, "fix_prompt": s.fixPrompt, "fix_plan": s.fixPlan, "list_runs": s.listRuns,
		"list_fixes": s.listFixes, "get_fix": s.getFix, "list_servers": s.listServers,
	}
	return s
}

type request struct {
	ID     json.RawMessage `json:"id"`
	Method any             `json:"method"`
	Params json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func errorResponse(id json.RawMessage, code int, msg string) pyfmt.Obj {
	return pyfmt.O("jsonrpc", "2.0", "id", id, "error", rpcError{code, msg})
}

// Handle one message; nil for notifications (no id). A message that is not a JSON object is a parse error.
func (s *Server) Handle(line []byte) any {
	resp, err := s.handle(line)
	if err != nil {
		fmt.Fprintf(s.Log, "mcp: %v\n", err)
		return errorResponse(json.RawMessage("null"), -32700, "parse error")
	}
	return resp
}

func (s *Server) handle(line []byte) (any, error) {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		return nil, err
	}
	if len(req.ID) == 0 || string(req.ID) == "null" { // notification (e.g. notifications/initialized)
		return nil, nil
	}
	var params map[string]any
	if len(req.Params) > 0 && string(req.Params) != "null" {
		d := json.NewDecoder(bytes.NewReader(req.Params))
		d.UseNumber()
		if err := d.Decode(&params); err != nil {
			return nil, fmt.Errorf("params: %w", err)
		}
	}
	method, _ := req.Method.(string)
	var result any
	switch method {
	case "initialize":
		pv := params["protocolVersion"]
		if !pyfmt.Truthy(pv) {
			pv = DefaultProtocol
		}
		result = pyfmt.O("protocolVersion", pv, "capabilities", pyfmt.O("tools", pyfmt.O("listChanged", false)),
			"serverInfo", pyfmt.O("name", "kanareika", "version", s.version), "instructions", Instructions)
	case "ping":
		result = pyfmt.Obj{}
	case "tools/list":
		result = pyfmt.O("tools", Tools)
	case "tools/call":
		name, _ := params["name"].(string)
		fn := s.tools[name]
		if fn == nil {
			return errorResponse(req.ID, -32602, "unknown tool "+pyfmt.Str(params["name"])), nil
		}
		a, _ := params["arguments"].(map[string]any)
		if a == nil {
			a = map[string]any{}
		}
		result = s.call(fn, a)
	default:
		return errorResponse(req.ID, -32601, "method not found: "+pyfmt.Str(req.Method)), nil
	}
	return pyfmt.O("jsonrpc", "2.0", "id", req.ID, "result", result), nil
}

// call runs a tool; its failures (and panics on unexpected data) are tool errors the agent sees, not protocol errors.
func (s *Server) call(fn func(args) (any, error), a args) (result any) {
	defer func() {
		if r := recover(); r != nil {
			result = toolError(fmt.Errorf("%v", r))
		}
	}()
	data, err := fn(a)
	if err != nil {
		return toolError(err)
	}
	text, ok := data.(string)
	if !ok {
		b, err := pyfmt.MarshalIndent(data)
		if err != nil {
			return toolError(err)
		}
		text = string(b)
	}
	return pyfmt.O("content", []any{pyfmt.O("type", "text", "text", text)})
}

func toolError(err error) pyfmt.Obj {
	return pyfmt.O("content", []any{pyfmt.O("type", "text", "text", "Error: "+err.Error())}, "isError", true)
}

// Serve reads requests from in and writes responses to out until EOF or ctx is done. Blank lines are skipped;
// every response is one line.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	lines := make(chan []byte)
	errc := make(chan error, 1)
	go func() {
		r := bufio.NewReaderSize(in, 1<<20)
		for {
			line, err := r.ReadBytes('\n')
			if len(bytes.TrimSpace(line)) > 0 {
				select {
				case lines <- line:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				errc <- err
				return
			}
		}
	}()
	w := bufio.NewWriter(out)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errc:
			return err
		case line := <-lines:
			resp := s.Handle(bytes.TrimSpace(line))
			if resp == nil {
				continue
			}
			// resp holds only strings and values decoded from JSON (tool results are already text): it always marshals
			b, _ := pyfmt.MarshalLine(resp, false)
			b = append(b, '\n')
			if _, err := w.Write(b); err != nil {
				return err
			}
			if err := w.Flush(); err != nil {
				return err
			}
		}
	}
}

// Serve is the `kanareika mcp` entry point: a server over the working directory p, until EOF on in.
func Serve(ctx context.Context, in io.Reader, out io.Writer, p config.Paths, version string) error {
	return NewServer(p, version).Serve(ctx, in, out)
}
