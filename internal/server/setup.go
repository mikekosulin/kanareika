package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/onboard"
	"github.com/mikekosulin/kanareika/internal/sshx"
)

// newConn: an SSH connection for the access check; tests replace it.
var newConn = func(o *config.Org, p config.Paths) (onboard.Runner, error) { return sshx.New(o, p) }

// setupNow: the date a new org's consent starts; tests replace it.
var setupNow = time.Now

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
	path, problems, err := onboard.Create(s.paths, req, setupNow().UTC())
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
	sendJSON(w, http.StatusCreated, map[string]any{"org": req.ID, "path": path})
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
		Org string `json:"org"`
		Env string `json:"env"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
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
		sendErr(w, http.StatusBadRequest, err.Error())
		return
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	sendJSON(w, http.StatusOK, map[string]any{"results": onboard.Check(ctx, o, req.Env, conn)})
}
