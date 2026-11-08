// Package dbget downloads the data kanareika needs (trivy's vulnerability DBs, KEV, EPSS, the IP databases) in
// parallel and reports progress: per download its state, bytes, speed and time left, and the same for all of them.
// The CLI draws it, the web page and the TUI show it from /api/db.
package dbget

import (
	"context"
	"io"
	"slices"
	"sync"
	"time"
)

// States of a download.
const (
	Queued      = "queued"
	Checking    = "checking"    // looking at what is cached and what is published
	Downloading = "downloading" // bytes are coming
	Unpacking   = "unpacking"
	Done        = "done"    // downloaded and in place
	Current     = "current" // the cached copy is the latest: nothing to download
	Failed      = "failed"
	Kept        = "kept" // the download failed, the cached copy stays in use
)

// Item: one download as the interfaces show it.
type Item struct {
	Name     string    `json:"name"`             // trivy-db, java-db, kev, epss, dbip-city, dbip-asn
	State    string    `json:"state"`            // see the states above
	Source   string    `json:"source,omitempty"` // the repository or URL in use
	Done     int64     `json:"done"`             // bytes received
	Total    int64     `json:"total"`            // bytes expected, 0: unknown
	Speed    float64   `json:"speed"`            // bytes per second, smoothed
	ETA      float64   `json:"eta"`              // seconds left, -1: unknown
	Note     string    `json:"note,omitempty"`   // what happened: "up to date", the error, the cached copy's age
	Started  time.Time `json:"started,omitzero"`
	Finished time.Time `json:"finished,omitzero"`
}

// Snapshot: all downloads and the totals.
type Snapshot struct {
	Items   []Item  `json:"items"`
	Done    int64   `json:"done"`
	Total   int64   `json:"total"` // of the downloads whose size is known
	Speed   float64 `json:"speed"`
	ETA     float64 `json:"eta"` // -1: unknown
	Running bool    `json:"running"`
}

// Job: one download. Run reports through p; it returns an error when nothing usable is in place.
type Job struct {
	Name string
	Run  func(ctx context.Context, p *Progress) error
}

// Progress: what a job reports; safe for concurrent use.
type Progress struct {
	t *Tracker
	i int
}

func (p *Progress) update(f func(*Item)) {
	p.t.mu.Lock()
	it := &p.t.items[p.i]
	f(it)
	p.t.mu.Unlock()
	p.t.changed()
}

// State sets the state (and the note, when given).
func (p *Progress) State(state string, note ...string) {
	p.update(func(it *Item) {
		it.State = state
		if len(note) > 0 {
			it.Note = note[0]
		}
		switch state {
		case Done, Current, Failed, Kept:
			it.Finished = p.t.now()
			it.Speed, it.ETA = 0, 0
			if state == Done && it.Total == 0 {
				it.Total = it.Done
			}
		}
	})
}

// Source: where it is being downloaded from.
func (p *Progress) Source(s string) { p.update(func(it *Item) { it.Source = s }) }

// Start: a download of total bytes (0: unknown) begins; bytes of an earlier attempt are forgotten.
func (p *Progress) Start(total int64) {
	p.update(func(it *Item) {
		it.State, it.Total, it.Done, it.Speed, it.ETA = Downloading, total, 0, 0, -1
		if it.Started.IsZero() {
			it.Started = p.t.now()
		}
		p.t.marks[p.i] = mark{p.t.now(), 0}
	})
}

// Reader: r with its bytes counted as this download's.
func (p *Progress) Reader(r io.Reader) io.Reader { return &counting{r, p} }

type counting struct {
	r io.Reader
	p *Progress
}

func (c *counting) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if n > 0 {
		c.p.add(int64(n))
	}
	return n, err
}

// mark: bytes at a moment, for the speed.
type mark struct {
	at   time.Time
	done int64
}

func (p *Progress) add(n int64) {
	t := p.t
	t.mu.Lock()
	it := &t.items[p.i]
	it.Done += n
	now := t.now()
	m := t.marks[p.i]
	if dt := now.Sub(m.at).Seconds(); dt >= 0.5 { // smoothed over half-second steps
		rate := float64(it.Done-m.done) / dt
		if it.Speed == 0 {
			it.Speed = rate
		} else {
			it.Speed = 0.7*it.Speed + 0.3*rate
		}
		t.marks[p.i] = mark{now, it.Done}
	}
	it.ETA = -1
	if it.Total > 0 && it.Speed > 0 {
		it.ETA = float64(max(0, it.Total-it.Done)) / it.Speed
	}
	t.mu.Unlock()
	t.changed()
}

// Tracker: the downloads of one update and who wants to hear about them.
type Tracker struct {
	mu      sync.Mutex
	items   []Item
	marks   []mark
	running bool
	notify  func(Snapshot)
	every   time.Duration
	last    time.Time
	now     func() time.Time
}

// NewTracker: notify gets a snapshot at most every `every` (and always at the end); nil notify is fine.
func NewTracker(notify func(Snapshot), every time.Duration) *Tracker {
	return &Tracker{notify: notify, every: every, now: time.Now}
}

func (t *Tracker) changed() {
	if t.notify == nil {
		return
	}
	t.mu.Lock()
	now := t.now()
	due := now.Sub(t.last) >= t.every
	if due {
		t.last = now
	}
	t.mu.Unlock()
	if due {
		t.notify(t.Snapshot())
	}
}

// Snapshot: the downloads now, with totals.
func (t *Tracker) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := Snapshot{Items: slices.Clone(t.items), Running: t.running, ETA: -1}
	unknown := false
	for _, it := range t.items {
		s.Done += it.Done
		s.Total += it.Total
		if it.State == Downloading {
			s.Speed += it.Speed
			if it.Total == 0 {
				unknown = true
			}
		}
	}
	if left := s.Total - s.Done; !unknown && s.Speed > 0 && left >= 0 {
		s.ETA = float64(left) / s.Speed
	}
	return s
}

// Run: the jobs in parallel; their errors by name (nil when all of them have something usable in place).
func (t *Tracker) Run(ctx context.Context, jobs []Job) map[string]error {
	t.mu.Lock()
	t.items, t.marks, t.running = make([]Item, len(jobs)), make([]mark, len(jobs)), true
	for i, j := range jobs {
		t.items[i] = Item{Name: j.Name, State: Queued, ETA: -1}
	}
	t.mu.Unlock()
	t.changed()
	errs := map[string]error{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := &Progress{t, i}
			err := j.Run(ctx, p)
			if err != nil {
				mu.Lock()
				errs[j.Name] = err
				mu.Unlock()
			}
			t.mu.Lock()
			st := t.items[i].State
			t.mu.Unlock()
			switch {
			case err != nil && st != Kept:
				p.State(Failed, err.Error())
			case err == nil && st != Current && st != Kept:
				p.State(Done)
			}
		}()
	}
	wg.Wait()
	t.mu.Lock()
	t.running = false
	t.last = time.Time{} // the final snapshot always goes out
	t.mu.Unlock()
	t.changed()
	if len(errs) == 0 {
		return nil
	}
	return errs
}
