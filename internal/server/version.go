package server

import (
	"net/http"
	"time"

	"github.com/mikekosulin/kanareika/internal/update"
)

// apiVersion: the running version and, when a newer release is out, which and where (internal/update: GitHub is
// asked at most once a day, the request waits for that check at most update.Timeout). "check": false when update
// checks are off here (KANAREIKA_UPDATE_CHECK=off, KANAREIKA_OFFLINE, a build that is not a release).
func (s *Server) apiVersion(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"version": s.version, "check": s.updatePath != "" && update.Enabled(s.version)}
	i := update.Check(r.Context(), s.updatePath, s.version, time.Now())
	if v := i.Newer(s.version); v != "" {
		out["latest"], out["url"] = v, i.URL
	}
	sendJSON(w, http.StatusOK, out)
}
