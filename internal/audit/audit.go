// Package audit captures per-request audit events from the Runveil
// proxy and persists them as JSON Lines to a rotating file.
//
// audit is a leaf package: it depends only on stdlib and
// gopkg.in/natefinch/lumberjack.v2 (rotation). It does not import
// any other runveil/internal/ package; producers pass values via
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
//	user         optional; developer identity (OS username or override)
//	machine      optional; hostname
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

	User    string `json:"user,omitempty"`    // developer identity
	Machine string `json:"machine,omitempty"` // hostname
	OrgID   string `json:"org_id,omitempty"`  // control-plane org id (from enrollment)
}

// Event is a synthetic (non-request) audit record. Currently used for
// policy reload notifications. Future synthetic event kinds reuse this
// shape with a different Kind value.
//
// Wire format (JSON tags):
//
//	time          RFC3339Nano UTC
//	kind          event discriminator (e.g., "policy_reload")
//	policy_path   absolute path that triggered the event (omitempty)
//	outcome       "accepted" | "rejected" (omitempty)
//	rules_before  rule count of the policy that was active before
//	              (omitempty when zero)
//	rules_after   rule count after a successful reload (omitempty when
//	              zero — also omitted on rejection)
//	error         the validation error string (omitempty — only set on
//	              rejection)
//	user          optional; developer identity (OS username or override)
//	machine       optional; hostname
type Event struct {
	Time        time.Time `json:"time"`
	Kind        string    `json:"kind"`
	PolicyPath  string    `json:"policy_path,omitempty"`
	Outcome     string    `json:"outcome,omitempty"`
	RulesBefore int       `json:"rules_before,omitempty"`
	RulesAfter  int       `json:"rules_after,omitempty"`
	Error       string    `json:"error,omitempty"`

	User    string `json:"user,omitempty"`    // developer identity
	Machine string `json:"machine,omitempty"` // hostname
	OrgID   string `json:"org_id,omitempty"`  // control-plane org id (from enrollment)
}

// Logger is the consumer-facing interface. Proxy holds a Logger (never
// a concrete *Writer) so tests can inject capturing or no-op
// implementations.
//
// Log emits one per-request record. Event emits one synthetic record
// (e.g., a policy reload notification). Both are async — implementations
// are free to drop on backpressure.
type Logger interface {
	Log(r Record)
	Event(e Event)
}

// NoopLogger discards records. Used as the default when no audit
// destination is configured.
type NoopLogger struct{}

// Log implements Logger by doing nothing.
func (NoopLogger) Log(_ Record) {}

// Event implements Logger by doing nothing.
func (NoopLogger) Event(_ Event) {}
