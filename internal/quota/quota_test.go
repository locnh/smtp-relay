package quota

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) count(s string) int { return strings.Count(b.String(), s) }

type env struct {
	clock *fakeClock
	logs  *syncBuffer
	file  string
	opts  Options
}

func newEnv(t *testing.T, ups ...UpstreamQuota) *env {
	t.Helper()
	e := &env{clock: newClock(), logs: &syncBuffer{}, file: filepath.Join(t.TempDir(), "state", "state.json")}
	e.opts = Options{
		Upstreams:     ups,
		StateFile:     e.file,
		Now:           e.clock.Now,
		FlushInterval: 5 * time.Millisecond,
		Log:           zerolog.New(e.logs),
	}
	return e
}

func (e *env) manager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(e.opts)
	require.NoError(t, err)
	return m
}

func ses(limit int64) UpstreamQuota {
	return UpstreamQuota{Name: "ses", Limit: limit, Window: time.Hour}
}

func recordN(m *Manager, name string, n int) {
	for i := 0; i < n; i++ {
		m.Record(name)
	}
}

func used(t *testing.T, m *Manager, name string) int64 {
	t.Helper()
	s, ok := m.Status(name)
	require.True(t, ok)
	return s.Used
}

func TestCountingAndPercent(t *testing.T) {
	m := newEnv(t, ses(8)).manager(t)
	recordN(m, "ses", 3)
	s, ok := m.Status("ses")
	require.True(t, ok)
	assert.Equal(t, Status{Upstream: "ses", Used: 3, Limit: 8}, s)
	assert.Equal(t, 37.5, s.Percent())
}

func TestStatusesOrderAndUnknown(t *testing.T) {
	m := newEnv(t, UpstreamQuota{Name: "b", Limit: 10, Window: time.Hour}, UpstreamQuota{Name: "a", Limit: 5, Window: time.Hour}).manager(t)
	m.Record("nope")
	m.Record("a")
	assert.Equal(t, []Status{{"b", 0, 10}, {"a", 1, 5}}, m.Statuses())
	_, ok := m.Status("nope")
	assert.False(t, ok)
}

func TestWindowSlides(t *testing.T) {
	e := newEnv(t, ses(100))
	m := e.manager(t)
	m.Record("ses")
	e.clock.Advance(30 * time.Minute)
	recordN(m, "ses", 2)
	assert.EqualValues(t, 3, used(t, m, "ses"))

	e.clock.Advance(31 * time.Minute)
	assert.EqualValues(t, 2, used(t, m, "ses"), "first message left the window")

	e.clock.Advance(30 * time.Minute)
	assert.EqualValues(t, 0, used(t, m, "ses"))
	assert.Empty(t, m.byName["ses"].buckets, "old buckets are pruned")
}

func TestBucketCountBounded(t *testing.T) {
	e := newEnv(t, ses(1000))
	m := e.manager(t)
	for i := 0; i < 500; i++ {
		m.Record("ses")
		e.clock.Advance(time.Minute)
	}
	assert.LessOrEqual(t, len(m.byName["ses"].buckets), 60)
	assert.EqualValues(t, 59, used(t, m, "ses"))
}

func TestOverLimitStillCounted(t *testing.T) {
	m := newEnv(t, ses(2)).manager(t)
	recordN(m, "ses", 5)
	s, _ := m.Status("ses")
	assert.EqualValues(t, 5, s.Used)
	assert.Equal(t, 250.0, s.Percent())
}

func TestThresholdWarningsOnceAndRearm(t *testing.T) {
	e := newEnv(t, ses(10))
	m := e.manager(t)
	const w80, w100 = "reached 80%", "reached 100%"

	recordN(m, "ses", 7)
	assert.Equal(t, 0, e.logs.count(w80))
	recordN(m, "ses", 1)
	assert.Equal(t, 1, e.logs.count(w80))
	recordN(m, "ses", 1)
	assert.Equal(t, 1, e.logs.count(w80))
	assert.Equal(t, 0, e.logs.count(w100))
	recordN(m, "ses", 5)
	assert.Equal(t, 1, e.logs.count(w100))
	assert.Equal(t, 1, e.logs.count(w80))

	e.clock.Advance(2 * time.Hour)
	recordN(m, "ses", 8)
	assert.Equal(t, 2, e.logs.count(w80), "re-armed after dropping below 80%")
	assert.Equal(t, 1, e.logs.count(w100))
	recordN(m, "ses", 2)
	assert.Equal(t, 2, e.logs.count(w100))
}

func TestNoWarningRepeatAfterRestartAboveThreshold(t *testing.T) {
	e := newEnv(t, ses(10))
	m := e.manager(t)
	recordN(m, "ses", 9)
	require.NoError(t, m.Close())

	e.logs.buf.Reset()
	m2 := e.manager(t)
	m2.Record("ses")
	assert.Equal(t, 0, e.logs.count("reached 80%"))
	assert.Equal(t, 1, e.logs.count("reached 100%"))
}

func TestPersistenceRoundTrip(t *testing.T) {
	e := newEnv(t, ses(100), UpstreamQuota{Name: "other", Limit: 5, Window: 24 * time.Hour})
	m := e.manager(t)
	recordN(m, "ses", 3)
	e.clock.Advance(5 * time.Minute)
	recordN(m, "ses", 4)
	m.Record("other")
	require.NoError(t, m.Close())
	require.NoError(t, m.Close(), "Close is idempotent")

	m2 := e.manager(t)
	assert.Equal(t, m.Statuses(), m2.Statuses())
	assert.EqualValues(t, 7, used(t, m2, "ses"))
}

func TestFileFormatPermissionsAndNoTempFiles(t *testing.T) {
	e := newEnv(t, ses(100))
	m := e.manager(t)
	m.Record("ses")
	require.NoError(t, m.flush())
	m.Record("ses")
	require.NoError(t, m.flush())

	info, err := os.Stat(e.file)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	data, err := os.ReadFile(e.file)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"version":1`)
	assert.Contains(t, string(data), fmt.Sprintf(`"%d":2`, m.nowMinute()))

	entries, err := os.ReadDir(filepath.Dir(e.file))
	require.NoError(t, err)
	require.Len(t, entries, 1, "only the state file remains")
	assert.Equal(t, "state.json", entries[0].Name())
}

func TestFlushOnlyWhenDirty(t *testing.T) {
	e := newEnv(t, ses(100))
	m := e.manager(t)
	require.NoError(t, m.flush())
	_, err := os.Stat(e.file)
	assert.True(t, os.IsNotExist(err))

	m.Record("ses")
	writes := 0
	m.write = func(p string, d []byte) error { writes++; return writeFileAtomic(p, d) }
	require.NoError(t, m.flush())
	require.NoError(t, m.flush())
	assert.Equal(t, 1, writes)
}

func TestCorruptFileRenamed(t *testing.T) {
	for name, content := range map[string]string{
		"garbage":       "not json{",
		"wrong version": `{"version":2,"upstreams":{}}`,
		"bad bucket":    `{"version":1,"upstreams":{"ses":{"buckets":{"x":1}}}}`,
		"negative":      `{"version":1,"upstreams":{"ses":{"buckets":{"1":-1}}}}`,
		"huge count":    `{"version":1,"upstreams":{"ses":{"buckets":{"1":1099511627777}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, ses(100))
			require.NoError(t, os.MkdirAll(filepath.Dir(e.file), 0o700))
			require.NoError(t, os.WriteFile(e.file, []byte(content), 0o600))

			m := e.manager(t)
			assert.EqualValues(t, 0, used(t, m, "ses"))
			assert.Contains(t, e.logs.String(), "corrupt quota state file")

			_, err := os.Stat(e.file)
			assert.True(t, os.IsNotExist(err))
			moved, err := filepath.Glob(e.file + ".corrupt-*")
			require.NoError(t, err)
			require.Len(t, moved, 1)
			assert.Contains(t, moved[0], fmt.Sprintf(".corrupt-%d", e.clock.Now().UnixNano()))
			b, _ := os.ReadFile(moved[0])
			assert.Equal(t, content, string(b))

			m.Record("ses")
			assert.EqualValues(t, 1, used(t, m, "ses"))
		})
	}
}

func TestMissingFileIsFine(t *testing.T) {
	e := newEnv(t, ses(100))
	m := e.manager(t)
	assert.EqualValues(t, 0, used(t, m, "ses"))
	assert.NotContains(t, e.logs.String(), "warn")
}

func TestLoadDropsInvalidBucketsAndUnknownUpstreams(t *testing.T) {
	e := newEnv(t, ses(100))
	now := e.clock.Now().Unix() / 60
	require.NoError(t, os.MkdirAll(filepath.Dir(e.file), 0o700))
	content := fmt.Sprintf(`{"version":1,"saved_at":"2026-10-22T10:00:00Z","upstreams":{
		"ses":{"buckets":{"%d":4,"%d":3,"%d":100,"%d":50,"%d":9}},
		"removed":{"buckets":{"%d":8}}}}`,
		now, now-59, now-60, now+1, now+1000, now)
	require.NoError(t, os.WriteFile(e.file, []byte(content), 0o600))

	m := e.manager(t)
	assert.EqualValues(t, 7, used(t, m, "ses"), "keeps now and now-59 only")
	assert.Equal(t, 1, e.logs.count(`"upstream":"removed"`))
	assert.Contains(t, e.logs.String(), "no longer configured")
	_, ok := m.Status("removed")
	assert.False(t, ok)
}

func TestNewFailsWhenDirNotCreatable(t *testing.T) {
	e := newEnv(t, ses(100))
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	e.opts.StateFile = filepath.Join(blocker, "sub", "state.json")
	_, err := New(e.opts)
	assert.Error(t, err)
}

func TestNewFailsWhenDirNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks do not apply to root")
	}
	e := newEnv(t, ses(100))
	dir := filepath.Dir(e.file)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, err := New(e.opts)
	assert.Error(t, err)
}

func TestNoUpstreamsNeedsNoStateFile(t *testing.T) {
	m, err := New(Options{})
	require.NoError(t, err)
	m.Record("x")
	assert.Empty(t, m.Statuses())
	assert.NoError(t, m.Close())
}

func TestWindowShorterThanOneMinuteIsClamped(t *testing.T) {
	e := newEnv(t, UpstreamQuota{Name: "ses", Limit: 10, Window: time.Second})
	m := e.manager(t)
	m.Record("ses")
	assert.EqualValues(t, 1, used(t, m, "ses"))
	e.clock.Advance(time.Minute)
	assert.EqualValues(t, 0, used(t, m, "ses"))
}

func TestRuntimeWriteFailureIsCountedAndRetried(t *testing.T) {
	e := newEnv(t, ses(100))
	m := e.manager(t)
	failing := true
	m.write = func(p string, d []byte) error {
		if failing {
			return errors.New("disk full")
		}
		return writeFileAtomic(p, d)
	}

	m.Record("ses")
	assert.Error(t, m.flush())
	assert.Error(t, m.flush())
	assert.EqualValues(t, 2, m.WriteErrors())
	assert.Equal(t, 1, e.logs.count("cannot write quota state file"), "error log is rate limited")

	m.Record("ses")
	assert.EqualValues(t, 2, used(t, m, "ses"), "Record keeps working")

	e.clock.Advance(2 * time.Minute)
	assert.Error(t, m.flush())
	assert.Equal(t, 2, e.logs.count("cannot write quota state file"))

	failing = false
	require.NoError(t, m.flush())
	_, err := os.Stat(e.file)
	assert.NoError(t, err, "data stayed dirty and was written once the failure cleared")
}

func TestRuntimeWriteFailureReadOnlyDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks do not apply to root")
	}
	e := newEnv(t, ses(100))
	m := e.manager(t)
	dir := filepath.Dir(e.file)
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	m.Record("ses")
	assert.Error(t, m.Close())
	assert.EqualValues(t, 1, m.WriteErrors())
	m.Record("ses")
	assert.EqualValues(t, 2, used(t, m, "ses"))
}

func TestRunFlushesWhenDirtyAndOnCancel(t *testing.T) {
	e := newEnv(t, ses(100))
	m := e.manager(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()

	m.Record("ses")
	require.Eventually(t, func() bool {
		_, err := os.Stat(e.file)
		return err == nil
	}, 5*time.Second, 2*time.Millisecond, "periodic flush wrote the file")

	m.Record("ses")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}

	m2 := e.manager(t)
	assert.EqualValues(t, 2, used(t, m2, "ses"), "final flush on cancel")
}

func TestConcurrentRecordAndStatuses(t *testing.T) {
	e := newEnv(t, ses(1000))
	m := e.manager(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				m.Record("ses")
				_ = m.Statuses()
				_, _ = m.Status("ses")
				_ = m.WriteErrors()
			}
		}()
	}
	wg.Wait()
	cancel()
	<-done
	assert.EqualValues(t, 800, used(t, m, "ses"))
	assert.EqualValues(t, 800, used(t, e.manager(t), "ses"))
}

func TestOversizedStateFileIsCorrupt(t *testing.T) {
	e := newEnv(t, ses(100))
	require.NoError(t, os.MkdirAll(filepath.Dir(e.file), 0o700))
	f, err := os.Create(e.file)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(maxStateSize+1))
	require.NoError(t, f.Close())

	m := e.manager(t)
	assert.EqualValues(t, 0, used(t, m, "ses"))
	assert.Contains(t, e.logs.String(), "too large")
	moved, _ := filepath.Glob(e.file + ".corrupt-*")
	assert.Len(t, moved, 1)
	_, err = os.Stat(e.file)
	assert.True(t, os.IsNotExist(err))
}

func TestHugeCountsDoNotOverflowPercent(t *testing.T) {
	assert.True(t, overPercent(math.MaxInt64, 1, 80))
	assert.True(t, overPercent(math.MaxInt64, math.MaxInt64, 100))
	assert.False(t, overPercent(math.MaxInt64/2, math.MaxInt64, 100))
	assert.True(t, overPercent(math.MaxInt64/2, math.MaxInt64, 49))
	assert.False(t, overPercent(5, 0, 80))

	e := newEnv(t, ses(math.MaxInt64))
	require.NoError(t, os.MkdirAll(filepath.Dir(e.file), 0o700))
	now := e.clock.Now().Unix() / 60
	content := fmt.Sprintf(`{"version":1,"upstreams":{"ses":{"buckets":{"%d":1099511627776}}}}`, now)
	require.NoError(t, os.WriteFile(e.file, []byte(content), 0o600))
	m := e.manager(t)
	assert.EqualValues(t, int64(1)<<40, used(t, m, "ses"))
	m.Record("ses")
	assert.EqualValues(t, int64(1)<<40+1, used(t, m, "ses"))
}

func TestNewRequiresStateFile(t *testing.T) {
	e := newEnv(t, ses(100))
	e.opts.StateFile = ""
	_, err := New(e.opts)
	assert.Error(t, err)
}

func TestStaleTempFilesRemoved(t *testing.T) {
	e := newEnv(t, ses(100))
	dir := filepath.Dir(e.file)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	mk := func(name string, age time.Duration) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
		ts := e.clock.Now().Add(-age)
		require.NoError(t, os.Chtimes(p, ts, ts))
		return p
	}
	oldTmp := mk("state.json.tmp-111", 2*time.Minute)
	oldProbe := mk("state.json.probe-222", time.Hour)
	freshTmp := mk("state.json.tmp-333", 5*time.Second)
	other := mk("unrelated.tmp-1", time.Hour)

	e.manager(t)
	for _, p := range []string{oldTmp, oldProbe} {
		_, err := os.Stat(p)
		assert.True(t, os.IsNotExist(err), p)
	}
	for _, p := range []string{freshTmp, other} {
		_, err := os.Stat(p)
		assert.NoError(t, err, p)
	}
}

func TestCorruptRenameDoesNotOverwrite(t *testing.T) {
	e := newEnv(t, ses(100))
	require.NoError(t, os.MkdirAll(filepath.Dir(e.file), 0o700))
	for i := 0; i < 3; i++ {
		require.NoError(t, os.WriteFile(e.file, []byte(fmt.Sprintf("bad%d", i)), 0o600))
		e.manager(t)
	}
	moved, err := filepath.Glob(e.file + ".corrupt-*")
	require.NoError(t, err)
	require.Len(t, moved, 3, "same clock reading must not collide")
	got := map[string]bool{}
	for _, p := range moved {
		b, _ := os.ReadFile(p)
		got[string(b)] = true
	}
	assert.Equal(t, map[string]bool{"bad0": true, "bad1": true, "bad2": true}, got)
}

func TestWindowEdgeInMemory(t *testing.T) {
	for _, tc := range []struct {
		after time.Duration
		want  int64
	}{{9 * time.Minute, 1}, {10 * time.Minute, 0}, {11 * time.Minute, 0}} {
		t.Run(tc.after.String(), func(t *testing.T) {
			e2 := newEnv(t, UpstreamQuota{Name: "ses", Limit: 10, Window: 10 * time.Minute})
			m2 := e2.manager(t)
			m2.Record("ses")
			e2.clock.Advance(tc.after)
			assert.Equal(t, tc.want, used(t, m2, "ses"))
			assert.Equal(t, tc.want, sumBuckets(m2.byName["ses"]), "running total matches buckets")
		})
	}
}

func sumBuckets(u *upstreamCounter) int64 {
	var s int64
	for _, n := range u.buckets {
		s += n
	}
	return s
}

func TestRunningTotalMatchesBuckets(t *testing.T) {
	e := newEnv(t, ses(1000))
	m := e.manager(t)
	for i := 0; i < 200; i++ {
		recordN(m, "ses", i%3)
		e.clock.Advance(time.Duration(i%7) * time.Minute)
		u := used(t, m, "ses")
		assert.Equal(t, sumBuckets(m.byName["ses"]), u)
	}
}

func TestTempFileCleanedOnWriteFailure(t *testing.T) {
	e := newEnv(t, ses(100))
	m := e.manager(t)
	require.NoError(t, os.Mkdir(e.file, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(e.file, "keep"), nil, 0o600))

	m.Record("ses")
	assert.Error(t, m.flush())
	assert.EqualValues(t, 1, m.WriteErrors())
	left, err := filepath.Glob(e.file + ".tmp-*")
	require.NoError(t, err)
	assert.Empty(t, left)
}

func TestRecordDuringSlowWriteStaysDirty(t *testing.T) {
	e := newEnv(t, ses(100))
	m := e.manager(t)
	started, release := make(chan struct{}), make(chan struct{})
	var writes [][]byte
	m.write = func(p string, d []byte) error {
		writes = append(writes, d)
		if len(writes) == 1 {
			close(started)
			<-release
		}
		return writeFileAtomic(p, d)
	}

	m.Record("ses")
	done := make(chan error)
	go func() { done <- m.flush() }()
	<-started
	m.Record("ses")
	close(release)
	require.NoError(t, <-done)

	require.NoError(t, m.flush())
	require.Len(t, writes, 2, "the Record that landed during the write is flushed next")
	m2 := e.manager(t)
	assert.EqualValues(t, 2, used(t, m2, "ses"))
}
