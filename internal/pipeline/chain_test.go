package pipeline

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recordingStage struct {
	name     string
	decision Decision
	err      error
	panic    any
	called   *int32
}

func (s *recordingStage) Name() string { return s.name }
func (s *recordingStage) Process(_ context.Context, _ *RequestCtx) (Decision, error) {
	atomic.AddInt32(s.called, 1)
	if s.panic != nil {
		panic(s.panic)
	}
	return s.decision, s.err
}

func newCtx() *RequestCtx {
	req := httptest.NewRequest("POST", "https://api.example.com/v1/chat", nil)
	return &RequestCtx{
		Req:       req,
		Host:      "api.example.com",
		Metadata:  map[string]any{},
		StartedAt: time.Now(),
	}
}

func TestChain_EmptyChainReturnsContinue(t *testing.T) {
	c := NewChain()
	dec, err := c.Run(context.Background(), newCtx())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec != Continue {
		t.Fatalf("expected Continue, got %v", dec)
	}
}

func TestChain_RunsStagesInRegistrationOrder(t *testing.T) {
	var order []string
	var mu sync.Mutex
	mkStage := func(name string) Stage {
		return &funcStage{
			name: name,
			fn: func(_ context.Context, _ *RequestCtx) (Decision, error) {
				mu.Lock()
				order = append(order, name)
				mu.Unlock()
				return Continue, nil
			},
		}
	}
	c := NewChain()
	c.Register(mkStage("a"))
	c.Register(mkStage("b"))
	c.Register(mkStage("c"))

	if _, err := c.Run(context.Background(), newCtx()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"a", "b", "c"}
	if len(order) != len(want) {
		t.Fatalf("got %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("got %v, want %v", order, want)
		}
	}
}

func TestChain_BlockHaltsChain(t *testing.T) {
	var called int32
	first := &recordingStage{name: "block", decision: Block, called: &called}
	var afterCalled int32
	after := &recordingStage{name: "after", decision: Continue, called: &afterCalled}

	c := NewChain()
	c.Register(first)
	c.Register(after)

	dec, err := c.Run(context.Background(), newCtx())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec != Block {
		t.Fatalf("expected Block, got %v", dec)
	}
	if atomic.LoadInt32(&afterCalled) != 0 {
		t.Fatalf("stage after Block must not be called, but was called %d times", afterCalled)
	}
}

func TestChain_PanicRecoveredAsContinue(t *testing.T) {
	var afterCalled int32
	c := NewChain()
	c.Register(&recordingStage{name: "panic", decision: Continue, panic: "boom", called: new(int32)})
	c.Register(&recordingStage{name: "after", decision: Continue, called: &afterCalled})

	dec, err := c.Run(context.Background(), newCtx())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec != Continue {
		t.Fatalf("expected Continue after panic, got %v", dec)
	}
	if atomic.LoadInt32(&afterCalled) != 1 {
		t.Fatalf("stage after recovered panic must be called once, got %d", afterCalled)
	}
}

func TestChain_StageErrorTreatedAsContinue(t *testing.T) {
	var afterCalled int32
	c := NewChain()
	c.Register(&recordingStage{name: "err", decision: Continue, err: errors.New("oops"), called: new(int32)})
	c.Register(&recordingStage{name: "after", decision: Continue, called: &afterCalled})

	dec, err := c.Run(context.Background(), newCtx())
	if err != nil {
		t.Fatalf("Chain.Run must not return errors to caller; got %v", err)
	}
	if dec != Continue {
		t.Fatalf("expected Continue, got %v", dec)
	}
	if atomic.LoadInt32(&afterCalled) != 1 {
		t.Fatalf("subsequent stage must still run after error; called %d times", afterCalled)
	}
}

func TestChain_ConcurrentRunsAreIsolated(t *testing.T) {
	stage := &funcStage{name: "annotate", fn: func(_ context.Context, rc *RequestCtx) (Decision, error) {
		rc.Metadata["x"] = 1
		return Continue, nil
	}}
	c := NewChain()
	c.Register(stage)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc := newCtx()
			if _, err := c.Run(context.Background(), rc); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if rc.Metadata["x"] != 1 {
				t.Errorf("metadata bleed between requests")
			}
		}()
	}
	wg.Wait()
}

// funcStage is a Stage backed by a function; used in tests above.
type funcStage struct {
	name string
	fn   func(context.Context, *RequestCtx) (Decision, error)
}

func (s *funcStage) Name() string { return s.name }
func (s *funcStage) Process(ctx context.Context, rc *RequestCtx) (Decision, error) {
	return s.fn(ctx, rc)
}
