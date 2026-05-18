// Package audit captures per-request audit events from the Railcore
// proxy and persists them as JSON Lines to a rotating file.
//
// audit is a leaf package: it depends only on stdlib and
// gopkg.in/natefinch/lumberjack.v2 (rotation). It does not import
// any other railcore/internal/ package; producers pass values via
// the Logger interface.
package audit

import (
	"time"
)

// Record is one audit event written as a JSON Lines entry.
//
// Wire format (JSON tags):
//
//	time         RFC3339Nano UTC
//	request_id   UUID emitted by the proxy
//	host         AI vendor host (e.g., "api.anthropic.com")
//	method       HTTP method
//	path         request path
//	status       HTTP response status
//	bytes_in     request body size
//	bytes_out    response body size streamed back
//	duration_ms  wall-clock total
//	vendor       optional; "openai" | "anthropic"
//	endpoint     optional; "chat.completions" | "messages"
//	decision     "continue" | "block"
//	findings     optional; per-detector findings serialized via their own MarshalJSON
type Record struct {
	Time       time.Time `json:"time"`
	RequestID  string    `json:"request_id"`
	Host       string    `json:"host"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Status     int       `json:"status"`
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
	DurationMs int64     `json:"duration_ms"`

	Vendor   string `json:"vendor,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Decision string `json:"decision"`
	Findings []any  `json:"findings,omitempty"`
}

// Logger is the consumer-facing interface. Proxy holds a Logger
// (never a concrete *Writer) so tests can inject capturing or no-op
// implementations.
type Logger interface {
	Log(r Record)
}

// NoopLogger discards records. Used as the default when no audit
// destination is configured.
type NoopLogger struct{}

// Log implements Logger by doing nothing.
func (NoopLogger) Log(_ Record) {}
