package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/onboard"
	"github.com/mikekosulin/kanareika/internal/sshx"
)

// newConn: an SSH connection for the access check; tests replace it.
var newConn = func(o *config.Org, p config.Paths) (onboard.Runner, error) { return sshx.New(o, p) }

// setupNow: the date a new org's consent starts; tests replace it.
var setupNow = time.Now

// lockOrgFile: holds the org's file for one read-modify-write (two adds at once would each write the file as they
// read it, and one's hosts would be lost); returns the unlock.
func (s *Server) lockOrgFile(id string) func() {
	m, _ := s.orgFiles.LoadOrStore(strings.TrimSpace(strings.ToLower(id)), &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// apiSetup: POST /api/setup {onboard.Request} -> 201 {org, path} or 400 {errors}. It writes an org file, so it is
// allowed where scans are (localhost, or with a token).
func (s *Server) apiSetup(w http.ResponseWriter, r *http.Request) {
	if s.jobs == nil {
		sendErr(w, http.StatusForbidden, "setup is disabled on this read-only dashboard")
		return
	}
	var req onboard.Request
	dec := json.NewDecoder(io.LimitReader(r.Body, 256<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		sendErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	unlock := s.lockOrgFile(req.ID)
	path, skipped, problems, err := onboard.CreateWithSkipped(s.paths, req, setupNow().UTC())
	unlock()
	switch {
	case errors.Is(err, onboard.ErrExists):
		sendErr(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		sendErr(w, http.StatusInternalServerError, err.Error())
		return
	case len(problems) > 0:
		sendJSON(w, http.StatusBadRequest, map[string]any{"errors": problems})
		return
	}
	s.reload()
	s.log.Printf("dashboard: organization %s created (%s)", req.ID, path)
	sendJSON(w, http.StatusCreated, map[string]any{"org": req.ID, "path": path, "skipped": skipped})
}

// apiSetupAdd: POST /api/setup/add {org, hosts, env, front, internet} -> 200 {added: [names]} or 400 {errors}: the
// hosts go into the org's file (ungrouped unless a line names a group); the old file stays as .bak.
func (s *Server) apiSetupAdd(w http.ResponseWriter, r *http.Request) {
	if s.jobs == nil {
		sendErr(w, http.StatusForbidden, "setup is disabled on this read-only dashboard")
		return
	}
	var req struct {
		Org string `json:"org"`
		onboard.Request
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		sendErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	// the org's file is read under its lock: another add renaming it into place (on Windows not atomic for a reader)
	// would make the org look gone for a moment
	unlock := s.lockOrgFile(req.Org)
	s.reload()
	if s.state.Load().byID[req.Org] == nil {
		unlock()
		sendErr(w, http.StatusNotFound, "unknown org")
		return
	}
	added, skipped, problems, err := onboard.AddWithSkipped(s.paths, req.Org, req.Request)
	if err == nil && len(problems) == 0 {
		s.reload() // still under the lock: the next add renames the file only after it is read
	}
	unlock()
	switch {
	case err != nil:
		sendErr(w, http.StatusInternalServerError, err.Error())
		return
	case len(problems) > 0:
		sendJSON(w, http.StatusBadRequest, map[string]any{"errors": problems})
		return
	}
	s.log.Printf("dashboard: %d hosts added to %s", len(added), req.Org)
	if skipped == nil {
		skipped = []string{}
	}
	sendJSON(w, http.StatusOK, map[string]any{"added": added, "skipped": skipped})
}

// apiSetupParse: POST /api/setup/parse {text} -> {hosts, errors}: what the setup understood of a pasted list, for
// the live preview. Writes nothing.
func (s *Server) apiSetupParse(w http.ResponseWriter, r *http.Request) {
	if s.jobs == nil {
		sendErr(w, http.StatusForbidden, "setup is disabled on this read-only dashboard")
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		sendErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	hosts, errs := onboard.ParseHosts(req.Text)
	if hosts == nil {
		hosts = []onboard.Host{}
	}
	if errs == nil {
		errs = []string{}
	}
	sendJSON(w, http.StatusOK, map[string]any{"hosts": hosts, "errors": errs})
}

// apiSetupDiscover: GET /api/setup/discover -> what this machine knows about SSH (~/.ssh/config hosts, keys in
// ~/.ssh and in the agent, the local user), to fill the setup form. Where scans are allowed only: it reads the
// files of the machine kanareika web runs on.
func (s *Server) apiSetupDiscover(w http.ResponseWriter, _ *http.Request) {
	if s.jobs == nil {
		sendErr(w, http.StatusForbidden, "setup is disabled on this read-only dashboard")
		return
	}
	sendJSON(w, http.StatusOK, discover())
}

// discover: onboard.Discover with the ssh-agent's keys counted; tests replace it.
var discover = func() onboard.Found {
	onboard.SetAgentKeys(func() int { k, _ := sshx.AgentKeys(); return len(k) })
	return onboard.Discover()
}

// apiSetupCheck: POST /api/setup/check {org, env} -> 200 {results}: logs in to every host of the env and runs
// `uname -sr`. Read-only on the servers; allowed where scans are.
func (s *Server) apiSetupCheck(w http.ResponseWriter, r *http.Request) {
	if s.jobs == nil {
		sendErr(w, http.StatusForbidden, "connecting to servers is disabled on this read-only dashboard")
		return
	}
	var req struct {
		Org   string   `json:"org"`
		Env   string   `json:"env"`
		Hosts []string `json:"hosts,omitempty"` // only these (the ones just added)
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		sendErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	s.reload()
	o := s.state.Load().byID[req.Org]
	if o == nil || !slices.Contains(o.Envs(), req.Env) {
		sendErr(w, http.StatusNotFound, "unknown org/env")
		return
	}
	conn, err := newConn(o, s.paths)
	if err != nil {
		// no way to log in at all (no key, no agent): every host fails the same way, with the same advice
		var out []onboard.Result
		for _, h := range o.Hosts {
			if h.Env == req.Env && (len(req.Hosts) == 0 || slices.Contains(req.Hosts, h.Name)) {
				out = append(out, onboard.Result{Host: h.Name, Address: h.Address, Error: err.Error(), Hint: onboard.Hint(err.Error())})
			}
		}
		sendJSON(w, http.StatusOK, map[string]any{"results": out})
		return
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	sendJSON(w, http.StatusOK, map[string]any{"results": onboard.Check(ctx, o, req.Env, conn, req.Hosts...)})
}
