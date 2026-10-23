package quota

import (
	"context"
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
		u := &upstreamCounter{name: q.Name, limit: q.Limit, windowMinutes: wm, buckets: map[int64]int64{}}
		m.order = append(m.order, u)
		m.byName[q.Name] = u
	}
	if len(m.order) == 0 {
		return m, nil
	}
	if err := checkWritable(m.stateFile); err != nil {
		return nil, err
	}
	m.load()
	for _, u := range m.order {
		used := u.used(m.nowMinute())
		u.warned80 = overPercent(used, u.limit, warnPercent)
		u.warned100 = overPercent(used, u.limit, 100)
	}
	return m, nil
}

func (m *Manager) nowMinute() int64 { return m.now().Unix() / 60 }

// used sums the buckets inside the window and prunes the older ones.
func (u *upstreamCounter) used(nowMin int64) int64 {
	cutoff := nowMin - u.windowMinutes
	var sum int64
	for minute, n := range u.buckets {
		if minute <= cutoff {
			delete(u.buckets, minute)
			continue
		}
		sum += n
	}
	return sum
}

// overPercent reports used >= pct% of limit without floating point.
func overPercent(used, limit int64, pct int64) bool {
	return limit > 0 && used*100 >= limit*pct
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
	if !overPercent(u.used(nowMin), u.limit, warnPercent) {
		u.warned80, u.warned100 = false, false
	}
	u.buckets[nowMin]++
	m.dirty = true

	used := u.used(nowMin)
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
	return Status{Upstream: u.name, Used: u.used(m.nowMinute()), Limit: u.limit}
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
		u.used(nowMin)
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
