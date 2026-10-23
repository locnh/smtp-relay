package relay

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/locnh/smtp-relay/internal/upstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSender struct {
	name  string
	err   error
	mu    sync.Mutex
	calls int
}

func (f *fakeSender) Name() string { return f.name }

func (f *fakeSender) Send(_ context.Context, _ string, _ []string, _ []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.err
}

func (f *fakeSender) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type event struct {
	kind     string // "attempt" or "failover"
	upstream string
	to       string
	class    upstream.Class
}

type recordObserver struct {
	mu     sync.Mutex
	events []event
}

func (o *recordObserver) OnAttempt(_ *Message, a Attempt) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, event{kind: "attempt", upstream: a.Upstream, class: a.Class})
}

func (o *recordObserver) OnFailover(_ *Message, from, to string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, event{kind: "failover", upstream: from, to: to})
}

func (o *recordObserver) Failovers() []event {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []event
	for _, e := range o.events {
		if e.kind == "failover" {
			out = append(out, e)
		}
	}
	return out
}

func newMsg() *Message {
	return &Message{ID: "id", From: "a@x.test", To: []string{"b@y.test"}, Data: []byte("Subject: hi\r\n\r\nbody")}
}

func classErr(c upstream.Class) error {
	return &upstream.Error{Class: c, Err: errors.New("boom")}
}

var failureCases = []struct {
	name string
	err  error
}{
	{"connect", classErr(upstream.ClassConnect)},
	{"tls", classErr(upstream.ClassTLS)},
	{"auth", classErr(upstream.ClassAuth)},
	{"timeout", classErr(upstream.ClassTimeout)},
	{"smtp 4xx", &upstream.Error{Class: upstream.ClassSMTP4xx, Code: 451, Message: "try later"}},
	{"smtp 5xx", &upstream.Error{Class: upstream.ClassSMTP5xx, Code: 550, Message: "no such user"}},
	{"non-smtp error", errors.New("plain")},
}

func TestDeliverFailoverToSecondWhenFirstFails(t *testing.T) {
	for _, tc := range failureCases {
		t.Run(tc.name, func(t *testing.T) {
			a := &fakeSender{name: "A", err: tc.err}
			b := &fakeSender{name: "B"}
			obs := &recordObserver{}
			r := New([]Sender{a, b}, obs)

			res := r.Deliver(context.Background(), newMsg())

			require.NoError(t, res.Err)
			assert.Equal(t, "B", res.Upstream)
			assert.True(t, res.Delivered())
			assert.Equal(t, 1, a.Calls())
			assert.Equal(t, 1, b.Calls())
			require.Len(t, res.Attempts, 2)
			assert.Equal(t, "A", res.Attempts[0].Upstream)
			assert.Equal(t, upstream.ClassOf(tc.err), res.Attempts[0].Class)
			assert.Equal(t, "B", res.Attempts[1].Upstream)
			assert.NoError(t, res.Attempts[1].Err)
			assert.Equal(t, []event{{kind: "failover", upstream: "A", to: "B"}}, obs.Failovers())
		})
	}
}

func TestDeliverStopsAtFirstSuccess(t *testing.T) {
	a := &fakeSender{name: "A"}
	b := &fakeSender{name: "B"}
	obs := &recordObserver{}
	r := New([]Sender{a, b}, obs)

	res := r.Deliver(context.Background(), newMsg())

	require.NoError(t, res.Err)
	assert.Equal(t, "A", res.Upstream)
	assert.Equal(t, 1, a.Calls())
	assert.Equal(t, 0, b.Calls())
	assert.Len(t, res.Attempts, 1)
	assert.Empty(t, obs.Failovers())
}

func TestDeliverAllFailReturnsLastError(t *testing.T) {
	lastErr := &upstream.Error{Class: upstream.ClassSMTP5xx, Code: 550, Message: "last"}
	cases := []struct {
		name    string
		senders []*fakeSender
	}{
		{"one", []*fakeSender{{name: "A", err: lastErr}}},
		{"two", []*fakeSender{{name: "A", err: errors.New("first")}, {name: "B", err: lastErr}}},
		{"three", []*fakeSender{{name: "A", err: errors.New("first")}, {name: "B", err: errors.New("second")}, {name: "C", err: lastErr}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ss := make([]Sender, len(tc.senders))
			for i, s := range tc.senders {
				ss[i] = s
			}
			obs := &recordObserver{}
			res := New(ss, obs).Deliver(context.Background(), newMsg())

			require.Error(t, res.Err)
			assert.Equal(t, "", res.Upstream)
			assert.False(t, res.Delivered())
			assert.Len(t, res.Attempts, len(tc.senders))
			assert.Equal(t, tc.senders[len(tc.senders)-1].err, res.Err)
			for _, s := range tc.senders {
				assert.Equal(t, 1, s.Calls())
			}
			assert.Len(t, obs.Failovers(), len(tc.senders)-1)
			for i, f := range obs.Failovers() {
				assert.Equal(t, tc.senders[i].name, f.upstream)
				assert.Equal(t, tc.senders[i+1].name, f.to)
			}
		})
	}
}

func TestDeliverOrderIsStableAcrossCalls(t *testing.T) {
	a := &fakeSender{name: "A", err: errors.New("down")}
	b := &fakeSender{name: "B"}
	c := &fakeSender{name: "C"}
	r := New([]Sender{a, b, c}, nil)

	for i := 0; i < 5; i++ {
		res := r.Deliver(context.Background(), newMsg())
		require.NoError(t, res.Err)
		require.Len(t, res.Attempts, 2)
		assert.Equal(t, "A", res.Attempts[0].Upstream)
		assert.Equal(t, "B", res.Attempts[1].Upstream)
	}
	assert.Equal(t, 5, a.Calls())
	assert.Equal(t, 5, b.Calls())
	assert.Equal(t, 0, c.Calls())
}

func TestDeliverZeroSenders(t *testing.T) {
	res := New(nil, nil).Deliver(context.Background(), newMsg())

	assert.ErrorIs(t, res.Err, ErrNoSenders)
	assert.Empty(t, res.Attempts)
	assert.Equal(t, "", res.Upstream)
}

func TestDeliverContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := &fakeSender{name: "A"}
	obs := &recordObserver{}

	res := New([]Sender{a}, obs).Deliver(ctx, newMsg())

	assert.ErrorIs(t, res.Err, context.Canceled)
	assert.Equal(t, "", res.Upstream)
	assert.Empty(t, res.Attempts)
	assert.Equal(t, 0, a.Calls())
	assert.Empty(t, obs.events)
}

func TestDeliverDoesNotCopyCallerSliceOrder(t *testing.T) {
	a := &fakeSender{name: "A"}
	b := &fakeSender{name: "B"}
	list := []Sender{a, b}
	r := New(list, nil)
	list[0] = b
	list[1] = a

	res := r.Deliver(context.Background(), newMsg())

	assert.Equal(t, "A", res.Upstream)
}

func TestDeliverConcurrent(t *testing.T) {
	a := &fakeSender{name: "A", err: errors.New("down")}
	b := &fakeSender{name: "B"}
	r := New([]Sender{a, b}, &recordObserver{})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := r.Deliver(context.Background(), newMsg())
			assert.Equal(t, "B", res.Upstream)
		}()
	}
	wg.Wait()
	assert.Equal(t, 50, a.Calls())
	assert.Equal(t, 50, b.Calls())
}

func TestReply(t *testing.T) {
	long := strings.Repeat("x", 300)
	cases := []struct {
		name         string
		err          error
		wantCode     int
		wantEnhanced [3]int
		wantText     string
	}{
		{
			name:         "smtp 4xx keeps code and message",
			err:          &upstream.Error{Class: upstream.ClassSMTP4xx, Code: 451, Message: "try later"},
			wantCode:     451,
			wantEnhanced: [3]int{4, 0, 0},
			wantText:     "try later",
		},
		{
			name:         "smtp 5xx keeps code and message",
			err:          &upstream.Error{Class: upstream.ClassSMTP5xx, Code: 550, Message: "no such user"},
			wantCode:     550,
			wantEnhanced: [3]int{5, 0, 0},
			wantText:     "no such user",
		},
		{
			name:         "wrapped smtp error",
			err:          fmt.Errorf("attempt: %w", &upstream.Error{Class: upstream.ClassSMTP5xx, Code: 554, Message: "rejected"}),
			wantCode:     554,
			wantEnhanced: [3]int{5, 0, 0},
			wantText:     "rejected",
		},
		{
			name:         "connect error without code",
			err:          &upstream.Error{Class: upstream.ClassConnect, Err: errors.New("dial tcp smtp.internal:587")},
			wantCode:     421,
			wantEnhanced: [3]int{4, 4, 0},
			wantText:     "Forwarding failed",
		},
		{
			name:         "non-smtp error",
			err:          errors.New("something"),
			wantCode:     421,
			wantEnhanced: [3]int{4, 4, 0},
			wantText:     "Forwarding failed",
		},
		{
			name:         "multiline message is flattened",
			err:          &upstream.Error{Class: upstream.ClassSMTP5xx, Code: 550, Message: "line one\r\nline two\nline three"},
			wantCode:     550,
			wantEnhanced: [3]int{5, 0, 0},
			wantText:     "line one  line two line three",
		},
		{
			name:         "long message is trimmed to 200 chars",
			err:          &upstream.Error{Class: upstream.ClassSMTP5xx, Code: 550, Message: long},
			wantCode:     550,
			wantEnhanced: [3]int{5, 0, 0},
			wantText:     strings.Repeat("x", 200),
		},
		{
			name:         "no senders",
			err:          ErrNoSenders,
			wantCode:     554,
			wantEnhanced: [3]int{5, 3, 0},
			wantText:     "No upstream configured",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, enh, text := Result{Err: tc.err}.Reply()
			assert.Equal(t, tc.wantCode, code)
			assert.Equal(t, tc.wantEnhanced, enh)
			assert.Equal(t, tc.wantText, text)
		})
	}
}
