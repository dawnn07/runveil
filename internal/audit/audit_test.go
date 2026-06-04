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

func TestEvent_MarshalJSON_AllFields(t *testing.T) {
	e := Event{
		Time:        time.Date(2026, 5, 19, 10, 1, 23, 0, time.UTC),
		Kind:        "policy_reload",
		PolicyPath:  "/etc/runveil/policy.yaml",
		Outcome:     "accepted",
		RulesBefore: 2,
		RulesAfter:  3,
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)
	for _, want := range []string{
		`"time":"2026-05-19T10:01:23Z"`,
		`"kind":"policy_reload"`,
		`"policy_path":"/etc/runveil/policy.yaml"`,
		`"outcome":"accepted"`,
		`"rules_before":2`,
		`"rules_after":3`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

func TestEvent_MarshalJSON_OmitsEmptyOptionals(t *testing.T) {
	e := Event{
		Time: time.Now(),
		Kind: "policy_reload",
	}
	data, _ := json.Marshal(e)
	s := string(data)
	for _, absent := range []string{
		`"policy_path"`,
		`"outcome"`,
		`"rules_before"`,
		`"rules_after"`,
		`"error"`,
	} {
		if strings.Contains(s, absent) {
			t.Errorf("field %s should be omitted when empty; got %s", absent, s)
		}
	}
}

func TestNoopLogger_EventIsSafe(t *testing.T) {
	var l Logger = NoopLogger{}
	for i := 0; i < 5; i++ {
		l.Event(Event{Kind: "policy_reload"})
	}
}

func TestRecord_MarshalJSON_IncludesUserMachine(t *testing.T) {
	r := Record{
		Time:      time.Now(),
		RequestID: "r1",
		Decision:  "continue",
		User:      "alice@corp.com",
		Machine:   "alice-mbp",
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)
	for _, want := range []string{`"user":"alice@corp.com"`, `"machine":"alice-mbp"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

func TestRecord_MarshalJSON_OmitsEmptyUserMachine(t *testing.T) {
	r := Record{Time: time.Now(), RequestID: "r1", Decision: "continue"}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)
	if strings.Contains(s, `"user"`) || strings.Contains(s, `"machine"`) {
		t.Errorf("empty user/machine should be omitted; got %s", s)
	}
}

func TestEvent_MarshalJSON_IncludesUserMachine(t *testing.T) {
	e := Event{
		Time:    time.Now(),
		Kind:    "policy_reload",
		User:    "bob@corp.com",
		Machine: "bob-x1",
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)
	for _, want := range []string{`"user":"bob@corp.com"`, `"machine":"bob-x1"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

func TestRecord_MarshalJSON_IncludesOrgID(t *testing.T) {
	r := Record{
		Time:      time.Now(),
		RequestID: "r1",
		Decision:  "continue",
		OrgID:     "org_acme",
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"org_id":"org_acme"`) {
		t.Errorf("missing org_id in:\n%s", data)
	}
}

func TestRecord_MarshalJSON_OmitsEmptyOrgID(t *testing.T) {
	r := Record{Time: time.Now(), RequestID: "r1", Decision: "continue"}
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), `"org_id"`) {
		t.Errorf("empty org_id should be omitted; got %s", data)
	}
}

func TestEvent_MarshalJSON_IncludesOrgID(t *testing.T) {
	e := Event{
		Time:  time.Now(),
		Kind:  "policy_reload",
		OrgID: "org_acme",
	}
	data, _ := json.Marshal(e)
	if !strings.Contains(string(data), `"org_id":"org_acme"`) {
		t.Errorf("missing org_id in event:\n%s", data)
	}
}
