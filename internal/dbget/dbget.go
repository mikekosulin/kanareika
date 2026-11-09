// Package dbget downloads the data kanareika needs (trivy's vulnerability DBs, KEV, EPSS, the IP databases) in
// parallel and reports progress: per download its state, bytes, speed and time left, and the same for all of them.
// The CLI draws it, the web page and the TUI show it from /api/db ("progress").
package dbget

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"time"
)

// States of a download, as /api/db shows them.
const (
	Queued      = "queued"
	Downloading = "downloading" // bytes are coming (or being unpacked)
	Done        = "done"        // downloaded and in place
	Cached      = "cached"      // the cached copy is the latest: nothing downloaded
	Failed      = "failed"      // the note says why; a cached copy may stay in use (see Kept)
)

// Item: one download as the interfaces show it.
type Item struct {
	Name  string `json:"name"`  // db, java-db, kev, epss, dbip-city, dbip-asn (the keys of /api/db/size)
	Label string `json:"label"` // what it is, for people
	Bytes int64  `json:"bytes"` // received
	Total int64  `json:"total"` // expected; 0: unknown
	Speed int64  `json:"speed"` // bytes per second, smoothed
	ETA   *int64 `json:"eta_s"` // seconds left; null: unknown
	State string `json:"state"` // queued, downloading, done, cached, failed
	Note  string `json:"note"`  // what happened: a mirror that failed and the next one, why it failed, "already up to date (cached)"
}

// Totals: all downloads together.
type Totals struct {
	Bytes int64  `json:"bytes"`
	Total int64  `json:"total"` // of the downloads whose size is known
	Speed int64  `json:"speed"`
	ETA   *int64 `json:"eta_s"` // null: unknown
}

// Snapshot: all downloads and the totals.
type Snapshot struct {
	Items   []Item `json:"items"`
	Totals  Totals `json:"totals"`
	Running bool   `json:"running"`
}

// Job: one download. Run reports through p; it returns an error when it failed (wrap it with Kept when a cached
// copy stays in use).
type Job struct {
	Name, Label string
	// Optional: a failure is reported but does not fail the update (the IP databases)
	Optional bool
	Run      func(ctx context.Context, p *Progress) error
}

// item: an Item with what the speed is computed from.
type item struct {
	Item
	speed   float64
	mark    time.Time // last speed sample
	markN   int64
	started time.Time
}

// Progress: what a job reports; safe for concurrent use. A nil *Progress ignores everything.
type Progress struct {
	t *Tracker
	i int
}

func (p *Progress) update(f func(*item)) {
	if p == nil {
		return
	}
	p.t.mu.Lock()
	it := &p.t.items[p.i]
	before := it.Item
	f(it)
	after := it.Item
	p.t.mu.Unlock()
	if before.State != after.State || before.Note != after.Note {
		p.t.event(after)
	}
}

// Start: a download of total bytes (0: unknown) begins; bytes of an earlier attempt are forgotten.
func (p *Progress) Start(total int64) {
	p.update(func(it *item) {
		now := p.t.now()
		it.State, it.Total, it.Bytes, it.speed = Downloading, total, 0, 0
		it.mark, it.markN = now, 0
		if it.started.IsZero() {
			it.started = now
		}
	})
}

// Note: what is happening now ("ghcr.io: too many requests (429), trying mirror.gcr.io").
func (p *Progress) Note(s string) { p.update(func(it *item) { it.Note = s }) }

// Cached: nothing to download, the cached copy is the latest.
func (p *Progress) Cached(note string) {
	p.update(func(it *item) { it.State, it.Note, it.speed = Cached, note, 0 })
}

// Reader: r with its bytes counted as this download's.
func (p *Progress) Reader(r io.Reader) io.Reader {
	if p == nil {
		return r
	}
	return &counting{r, p}
}

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

func (p *Progress) add(n int64) {
	t := p.t
	t.mu.Lock()
	it := &t.items[p.i]
	it.Bytes += n
	t.sample(it, t.now())
	t.mu.Unlock()
}

// sample: the smoothed speed over half-second steps; a stalled download slows down to 0. Under t.mu.
func (t *Tracker) sample(it *item, now time.Time) {
	dt := now.Sub(it.mark).Seconds()
	if dt < 0.5 || it.State != Downloading {
		return
	}
	rate := float64(it.Bytes-it.markN) / dt
	if it.speed == 0 && it.Bytes > 0 && it.markN == 0 {
		it.speed = rate
	} else {
		it.speed = 0.7*it.speed + 0.3*rate
	}
	it.mark, it.markN = now, it.Bytes
}

// Tracker: the downloads of one update.
type Tracker struct {
	mu      sync.Mutex
	items   []item
	running bool
	now     func() time.Time
	// OnEvent: called (outside the lock) when a download changes state or note; the plain CLI output prints it.
	// It is called concurrently, from the goroutines of the jobs running in parallel: guard what it touches.
	OnEvent func(Item)
}

// NewTracker: an empty tracker; Run fills it.
func NewTracker() *Tracker { return &Tracker{now: time.Now} }

func (t *Tracker) event(it Item) {
	if t.OnEvent != nil {
		t.OnEvent(it)
	}
}

func eta(left int64, speed float64) *int64 {
	if speed < 1 || left < 0 {
		return nil
	}
	s := int64(float64(left)/speed + 0.5)
	return &s
}

// Snapshot: the downloads now, with totals.
func (t *Tracker) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	s := Snapshot{Items: make([]Item, 0, len(t.items)), Running: t.running}
	unknown, downloading := false, false
	var speed float64
	for i := range t.items {
		it := &t.items[i]
		t.sample(it, now)
		out := it.Item
		out.Speed, out.ETA = 0, nil
		if it.State == Downloading {
			downloading = true
			out.Speed = int64(it.speed + 0.5)
			speed += it.speed
			if it.Total > 0 {
				out.ETA = eta(it.Total-it.Bytes, it.speed)
			} else {
				unknown = true
			}
		}
		s.Items = append(s.Items, out)
		s.Totals.Bytes += it.Bytes
		s.Totals.Total += it.Total
	}
	s.Totals.Speed = int64(speed + 0.5)
	if downloading && !unknown {
		s.Totals.ETA = eta(s.Totals.Total-s.Totals.Bytes, speed)
	}
	return s
}

// Run: the jobs in parallel; their errors by name (nil when none failed).
func (t *Tracker) Run(ctx context.Context, jobs []Job) map[string]error {
	t.mu.Lock()
	t.items, t.running = make([]item, len(jobs)), true
	for i, j := range jobs {
		t.items[i] = item{Item: Item{Name: j.Name, Label: j.Label, State: Queued}}
	}
	t.mu.Unlock()
	errs := map[string]error{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Go(func() {
			p := &Progress{t, i}
			err := j.Run(ctx, p)
			if err != nil {
				mu.Lock()
				errs[j.Name] = err
				mu.Unlock()
			}
			p.update(func(it *item) {
				switch {
				case err != nil:
					it.State, it.Note = Failed, Reason(err)
				case it.State != Cached:
					it.State = Done
					if it.Total == 0 || it.Bytes > it.Total {
						it.Total = it.Bytes
					}
					if (it.Note == "" || it.Note == "unpacking") && !it.started.IsZero() {
						it.Note = "in " + Seconds(max(t.now().Sub(it.started), time.Second).Round(time.Second))
					}
				}
				it.speed = 0
			})
		})
	}
	wg.Wait()
	t.mu.Lock()
	t.running = false
	t.mu.Unlock()
	if len(errs) == 0 {
		return nil
	}
	return errs
}

// Names: the jobs' names, in order.
func Names(jobs []Job) []string {
	out := make([]string, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, j.Name)
	}
	return out
}

// KeptError: a download failed, and the cached copy stays in use.
type KeptError struct {
	Err  error
	Note string // "the copy from 2026-11-08 14:00Z (19 h old) stays in use"
}

func (e *KeptError) Error() string  { return e.Err.Error() + "; " + e.Note }
func (e *KeptError) Unwrap() error  { return e.Err }
func (e *KeptError) Reason() string { return Reason(e.Err) + "; " + e.Note }

// Kept: err, with the cached copy still in use.
func Kept(err error, note string) error { return &KeptError{err, note} }

// Fatal: the errors that leave something needed missing (not Kept, not of an optional job), joined; nil when none.
func Fatal(jobs []Job, errs map[string]error) error {
	var out []error
	for _, j := range jobs {
		err := errs[j.Name]
		var kept *KeptError
		if err == nil || j.Optional || errors.As(err, &kept) {
			continue
		}
		out = append(out, errors.New(j.Label+": "+Reason(err)))
	}
	return errors.Join(out...)
}

type ctxKey struct{}

// WithTracker: ctx carrying t, for an update started through an interface that shows its progress.
func WithTracker(ctx context.Context, t *Tracker) context.Context {
	return context.WithValue(ctx, ctxKey{}, t)
}

// TrackerFrom: the tracker ctx carries; nil when none.
func TrackerFrom(ctx context.Context) *Tracker {
	t, _ := ctx.Value(ctxKey{}).(*Tracker)
	return t
}

// Labels: the order and the names people see.
var Labels = map[string]string{
	"db":        "Vulnerability DB (trivy-db)",
	"java-db":   "Java DB (trivy-java-db)",
	"kev":       "CISA KEV",
	"epss":      "EPSS scores",
	"dbip-city": "IP locations (DB-IP city)",
	"dbip-asn":  "IP networks (DB-IP ASN)",
}

// Order: the jobs' order on every screen.
var Order = []string{"db", "java-db", "dbip-city", "dbip-asn", "kev", "epss"}

// Sort: jobs in Order.
func Sort(jobs []Job) {
	slices.SortStableFunc(jobs, func(a, b Job) int {
		return slices.Index(Order, a.Name) - slices.Index(Order, b.Name)
	})
}
