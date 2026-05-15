// Package pipeline defines the Stage interface and Chain dispatcher used
// by the Railcore proxy to run extensible request-processing stages.
//
// pipeline is a leaf package: it must not import any other internal/ package.
package pipeline

import (
	"context"
	"net/http"
	"time"
)

// Decision is the result a Stage returns after processing a request.
type Decision int

const (
	// Continue passes control to the next stage.
	Continue Decision = iota
	// Block halts the chain. The proxy returns 403 to the client without
	// dialling upstream.
	Block
	// Modify is a hint that the current stage mutated rc.Req. The proxy
	// treats Modify identically to Continue in this release.
	Modify
)

// String returns a stable lowercase name for the decision, suitable for logs.
func (d Decision) String() string {
	switch d {
	case Continue:
		return "continue"
	case Block:
		return "block"
	case Modify:
		return "modify"
	default:
		return "unknown"
	}
}

// RequestCtx is the per-request value threaded through every Stage.
// Stages may read rc.Req, annotate rc.Metadata, and (for Modify decisions)
// mutate rc.Req. Concurrent access by other goroutines is not supported.
type RequestCtx struct {
	Req       *http.Request
	Host      string
	Metadata  map[string]any
	StartedAt time.Time
}

// Stage is a single processing step in the request pipeline.
type Stage interface {
	Name() string
	Process(ctx context.Context, rc *RequestCtx) (Decision, error)
}
