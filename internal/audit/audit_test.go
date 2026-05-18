package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRecord_MarshalJSON_AllFields(t *testing.T) {
	r := Record{
		Time:       time.Date(2026, 5, 17, 16, 33, 12, 0, time.UTC),
		RequestID:  "abc-123",
		Host:       "api.anthropic.com",
		Method:     "POST",
		Path:       "/v1/messages",
		Status:     403,
		BytesIn:    1842,
		BytesOut:   196,
		DurationMs: 42,
		Vendor:     "anthropic",
		Endpoint:   "messages",
		Decision:   "block",
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		`"time":"2026-05-17T16:33:12Z"`,
		`"request_id":"abc-123"`,
		`"host":"api.anthropic.com"`,
		`"method":"POST"`,
		`"path":"/v1/messages"`,
		`"status":403`,
		`"bytes_in":1842`,
		`"bytes_out":196`,
		`"duration_ms":42`,
		`"vendor":"anthropic"`,
		`"endpoint":"messages"`,
		`"decision":"block"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in marshaled output:\n%s", want, s)
		}
	}
}

func TestRecord_MarshalJSON_OmitsEmptyOptionals(t *testing.T) {
	r := Record{
		Time:       time.Now(),
		RequestID:  "x",
		Host:       "example.com",
		Method:     "GET",
		Path:       "/",
		Status:     200,
		BytesIn:    0,
		BytesOut:   0,
		DurationMs: 0,
		Decision:   "continue",
		// Vendor, Endpoint, Findings deliberately omitted.
	}
	data, _ := json.Marshal(r)
	s := string(data)
	if strings.Contains(s, `"vendor"`) {
		t.Errorf("vendor should be omitted when empty; got %s", s)
	}
	if strings.Contains(s, `"endpoint"`) {
		t.Errorf("endpoint should be omitted when empty; got %s", s)
	}
	if strings.Contains(s, `"findings"`) {
		t.Errorf("findings should be omitted when empty; got %s", s)
	}
}

func TestNoopLogger_LogIsSafe(t *testing.T) {
	var l Logger = NoopLogger{}
	// Multiple calls must not panic.
	for i := 0; i < 10; i++ {
		l.Log(Record{RequestID: "test"})
	}
}
