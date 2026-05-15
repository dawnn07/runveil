package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
)

// Chain dispatches a sequence of registered Stages over a RequestCtx.
//
// Chain is safe for concurrent use after all Register calls complete.
// Register itself is NOT safe to call concurrently with Run.
type Chain struct {
	stages []Stage
	log    *slog.Logger
}

// NewChain returns an empty Chain that logs to slog.Default().
func NewChain() *Chain {
	return &Chain{log: slog.Default()}
}

// WithLogger returns a copy of c that uses log instead of slog.Default().
func (c *Chain) WithLogger(log *slog.Logger) *Chain {
	cp := *c
	cp.log = log
	return &cp
}

// Register adds s to the end of the chain.
func (c *Chain) Register(s Stage) {
	c.stages = append(c.stages, s)
}

// Run executes each stage in order. The first stage to return Block halts
// the chain and Run returns Block. Stages that panic or return a non-nil
// error are logged and treated as Continue (fail-open).
func (c *Chain) Run(ctx context.Context, rc *RequestCtx) (Decision, error) {
	for _, s := range c.stages {
		dec, err := c.runStage(ctx, s, rc)
		if dec == Block {
			return Block, nil
		}
		if err != nil {
			c.log.Warn("pipeline stage returned error",
				"stage", s.Name(),
				"host", rc.Host,
				"err", err.Error())
			// Treat as Continue (fail-open).
			continue
		}
		// Continue or Modify both proceed; nothing to do.
		_ = dec
	}
	return Continue, nil
}

func (c *Chain) runStage(ctx context.Context, s Stage, rc *RequestCtx) (dec Decision, err error) {
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("pipeline stage panicked",
				"stage", s.Name(),
				"host", rc.Host,
				"panic", fmt.Sprint(r),
				"stack", string(debug.Stack()))
			dec = Continue
			err = nil
		}
	}()
	return s.Process(ctx, rc)
}
