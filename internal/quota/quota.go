package quota

import (
	"context"
	"errors"
	"math"
	"math/bits"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const (
	defaultFlushInterval = 10 * time.Second
	writeErrLogInterval  = time.Minute
	warnPercent          = 80
)

// UpstreamQuota is the soft quota of one upstream, counted in messages.
type UpstreamQuota struct {
	Name   string
	Limit  int64
	Window time.Duration
}

// Options configures a Manager.
type Options struct {
	Upstreams     []UpstreamQuota // only upstreams that have a quota
	StateFile     string          // required when len(Upstreams) > 0
	Now           func() time.Time
	FlushInterval time.Duration
	Log           zerolog.Logger
}

type upstreamCounter struct {
	name          string
	limit         int64
	windowMinutes int64
	buckets       map[int64]int64 // unix minute -> messages
	total         int64           // sum of buckets
	pruned        int64           // minute of the last prune
	warned80      bool
	warned100     bool
}

// Manager keeps sliding-window message counts per upstream and persists them.
// The quota is soft: nothing is ever refused.
type Manager struct {
	stateFile string
	now       func() time.Time
	interval  time.Duration
	log       zerolog.Logger
	write     func(path string, data []byte) error

	mu       sync.Mutex
	order    []*upstreamCounter
	byName   map[string]*upstreamCounter
	dirty    bool
	writeErr uint64
	lastErr  time.Time

	flushMu sync.Mutex // serialises state file writes
}

// New creates the state directory if needed, verifies it is writable (an
// error here is meant to fail startup) and loads the existing state.
// A window shorter than one minute is clamped to one minute, the bucket size.
func New(o Options) (*Manager, error) {
	m := &Manager{
		stateFile: o.StateFile,
		now:       o.Now,
		interval:  o.FlushInterval,
		log:       o.Log,
		write:     writeFileAtomic,
		byName:    make(map[string]*upstreamCounter, len(o.Upstreams)),
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.interval <= 0 {
		m.interval = defaultFlushInterval
	}
	for _, q := range o.Upstreams {
		if _, dup := m.byName[q.Name]; dup {
			continue
		}
		wm := int64((q.Window + time.Minute - 1) / time.Minute)
		if wm < 1 {
			wm = 1
		}
		u := &upstreamCounter{name: q.Name, limit: q.Limit, windowMinutes: wm, buckets: map[int64]int64{}, pruned: math.MinInt64}
		m.order = append(m.order, u)
		m.byName[q.Name] = u
	}
	if len(m.order) == 0 {
		return m, nil
	}
	if m.stateFile == "" {
		return nil, errors.New("quota: state file is required when upstreams have a quota")
	}
	if err := checkWritable(m.stateFile, m.now()); err != nil {
		return nil, err
	}
	m.load()
	nowMin := m.nowMinute()
	for _, u := range m.order {
		u.advance(nowMin)
		u.warned80 = overPercent(u.total, u.limit, warnPercent)
		u.warned100 = overPercent(u.total, u.limit, 100)
	}
	return m, nil
}

func (m *Manager) nowMinute() int64 { return m.now().Unix() / 60 }

// add puts n messages into the bucket of the given minute.
func (u *upstreamCounter) add(minute, n int64) {
	u.buckets[minute] += n
	u.total += n
}

// advance drops buckets that left the window as of the current clock reading.
// It only walks the buckets when the minute differs from the last call, so the
// per-message cost stays O(1); a clock that moves backwards is handled too,
// because the cutoff always comes from the current minute.
func (u *upstreamCounter) advance(nowMin int64) {
	if nowMin == u.pruned {
		return
	}
	cutoff := nowMin - u.windowMinutes
	for minute, n := range u.buckets {
		if minute <= cutoff {
			delete(u.buckets, minute)
			u.total -= n
		}
	}
	u.pruned = nowMin
}

// overPercent reports used >= pct% of limit with a 128-bit comparison so huge
// values cannot overflow.
func overPercent(used, limit, pct int64) bool {
	if limit <= 0 || used < 0 {
		return false
	}
	uh, ul := bits.Mul64(uint64(used), 100)
	lh, ll := bits.Mul64(uint64(limit), uint64(pct))
	return uh > lh || (uh == lh && ul >= ll)
}

// Record counts one delivered message for upstream. Unknown names are ignored.
func (m *Manager) Record(upstream string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byName[upstream]
	if !ok {
		return
	}
	nowMin := m.nowMinute()
	u.advance(nowMin)
	if !overPercent(u.total, u.limit, warnPercent) {
		u.warned80, u.warned100 = false, false
	}
	u.add(nowMin, 1)
	m.dirty = true

	used := u.total
	if !u.warned80 && overPercent(used, u.limit, warnPercent) {
		u.warned80 = true
		m.log.Warn().Str("upstream", u.name).Int64("used", used).Int64("limit", u.limit).
			Msg("upstream quota reached 80%")
	}
	if !u.warned100 && overPercent(used, u.limit, 100) {
		u.warned100 = true
		m.log.Warn().Str("upstream", u.name).Int64("used", used).Int64("limit", u.limit).
			Msg("upstream quota reached 100%, mail is still delivered")
	}
}

// Status returns the current quota status of one upstream.
func (m *Manager) Status(upstream string) (Status, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byName[upstream]
	if !ok {
		return Status{}, false
	}
	return m.status(u), true
}

// Statuses returns one Status per configured upstream, in configuration order.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.order))
	for _, u := range m.order {
		out = append(out, m.status(u))
	}
	return out
}

func (m *Manager) status(u *upstreamCounter) Status {
	u.advance(m.nowMinute())
	return Status{Upstream: u.name, Used: u.total, Limit: u.limit}
}

// WriteErrors returns the number of failed state writes so far.
func (m *Manager) WriteErrors() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeErr
}

// Run flushes the state every FlushInterval while it is dirty and does a final
// flush when ctx is done.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = m.flush()
			return
		case <-t.C:
			_ = m.flush()
		}
	}
}

// Close does a final flush. It can be called more than once.
func (m *Manager) Close() error { return m.flush() }

// flush writes the state file if there are unsaved changes. On failure the
// data stays dirty so the next flush retries; the failure is counted and logged
// at most once per minute.
func (m *Manager) flush() error {
	m.flushMu.Lock()
	defer m.flushMu.Unlock()

	m.mu.Lock()
	if !m.dirty || len(m.order) == 0 {
		m.mu.Unlock()
		return nil
	}
	nowMin := m.nowMinute()
	snap := make(map[string]map[int64]int64, len(m.order))
	for _, u := range m.order {
		u.advance(nowMin)
		b := make(map[int64]int64, len(u.buckets))
		for k, v := range u.buckets {
			b[k] = v
		}
		snap[u.name] = b
	}
	m.dirty = false
	m.mu.Unlock()

	data, err := encodeState(m.now(), snap)
	if err == nil {
		err = m.write(m.stateFile, data)
	}
	if err == nil {
		return nil
	}

	m.mu.Lock()
	m.dirty = true
	m.writeErr++
	now := m.now()
	shouldLog := m.lastErr.IsZero() || now.Sub(m.lastErr) >= writeErrLogInterval
	if shouldLog {
		m.lastErr = now
	}
	m.mu.Unlock()
	if shouldLog {
		m.log.Error().Err(err).Str("file", m.stateFile).Msg("cannot write quota state file")
	}
	return err
}
