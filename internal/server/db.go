package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// DBUpdateFunc: what `kanareika db update` does (vulnerability DBs, KEV/EPSS, IP database), its output to out.
type DBUpdateFunc func(ctx context.Context, out io.Writer) error

// dbUpdater: one DB update at a time, started from an interface; its output and outcome stay for the next look.
type dbUpdater struct {
	fn  DBUpdateFunc
	now func() time.Time

	mu       sync.Mutex
	running  bool
	started  time.Time
	finished time.Time
	out      []string
	err      string
	cancel   context.CancelFunc
	done     chan struct{}
}

type dbLines struct{ u *dbUpdater }

func (w dbLines) Write(p []byte) (int, error) {
	w.u.mu.Lock()
	defer w.u.mu.Unlock()
	w.u.out = append(w.u.out, strings.Split(strings.TrimRight(string(p), "\n"), "\n")...)
	if n := len(w.u.out); n > 200 {
		w.u.out = w.u.out[n-200:]
	}
	return len(p), nil
}

// start: false when one is running already.
func (u *dbUpdater) start() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.running {
		return false
	}
	ctx, cancel := context.WithCancel(context.Background())
	u.running, u.started, u.finished, u.out, u.err, u.cancel, u.done = true, u.now(), time.Time{}, nil, "", cancel, make(chan struct{})
	go func() {
		defer close(u.done)
		err := u.fn(ctx, dbLines{u})
		u.mu.Lock()
		defer u.mu.Unlock()
		u.running, u.finished = false, u.now()
		if err != nil {
			u.err = err.Error()
		}
		cancel()
	}()
	return true
}

// stop: cancels a running update and waits for it.
func (u *dbUpdater) stop() {
	u.mu.Lock()
	cancel, done := u.cancel, u.done
	u.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// embeddedTrivy: the version of the trivy built into this binary ("" when unknown); a variable for tests.
var embeddedTrivy = trivy.Embedded

// apiDB: the DBs scans use (when downloaded, whether a newer build is out), the feeds, and the update in progress.
func (s *Server) apiDB(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	var dbs []map[string]any
	for _, d := range trivy.DBStatus() {
		e := map[string]any{"name": d.Name, "outdated": d.Outdated(now)}
		if !d.Updated.IsZero() {
			e["updated"] = d.Updated.UTC().Format(time.RFC3339)
		}
		if !d.Next.IsZero() {
			e["next_update"] = d.Next.UTC().Format(time.RFC3339)
		}
		dbs = append(dbs, e)
	}
	feeds, _ := priority.LoadFeeds()
	out := map[string]any{"dbs": dbs, "feeds_updated": feeds.Updated, "enabled": s.db != nil, "trivy": embeddedTrivy()}
	if u := s.db; u != nil {
		u.mu.Lock()
		out["updating"], out["output"], out["error"] = u.running, append([]string{}, u.out...), u.err
		if !u.finished.IsZero() {
			out["finished"] = u.finished.UTC().Format(time.RFC3339)
		}
		u.mu.Unlock()
	}
	sendJSON(w, http.StatusOK, out)
}

// apiDBUpdate: starts `db update`; 409 while one runs, 403 where updates are off (read-only).
func (s *Server) apiDBUpdate(w http.ResponseWriter, _ *http.Request) {
	switch {
	case s.db == nil:
		sendJSON(w, http.StatusForbidden, map[string]string{"error": "DB updates are off here (read-only)"})
	case !s.db.start():
		sendJSON(w, http.StatusConflict, map[string]string{"error": "a DB update is already running"})
	default:
		sendJSON(w, http.StatusAccepted, map[string]any{"started": true})
	}
}
