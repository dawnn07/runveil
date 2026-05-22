package audit

import (
	"testing"
	"time"
)

func TestIdentityLogger_StampsLogRecord(t *testing.T) {
	fake := &fakeLogger{}
	l := NewIdentityLogger(fake, Identity{User: "alice", Machine: "alice-mbp"})
	l.Log(Record{Time: time.Now(), RequestID: "r1", Decision: "continue"})

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.records) != 1 {
		t.Fatalf("got %d records, want 1", len(fake.records))
	}
	got := fake.records[0]
	if got.User != "alice" || got.Machine != "alice-mbp" {
		t.Errorf("stamped identity = %q/%q, want alice/alice-mbp", got.User, got.Machine)
	}
}

func TestIdentityLogger_StampsEvent(t *testing.T) {
	fake := &fakeLogger{}
	l := NewIdentityLogger(fake, Identity{User: "bob", Machine: "bob-x1"})
	l.Event(Event{Time: time.Now(), Kind: "policy_reload"})

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.events) != 1 {
		t.Fatalf("got %d events, want 1", len(fake.events))
	}
	got := fake.events[0]
	if got.User != "bob" || got.Machine != "bob-x1" {
		t.Errorf("stamped identity = %q/%q, want bob/bob-x1", got.User, got.Machine)
	}
}

func TestIdentityLogger_OverwritesPresetIdentity(t *testing.T) {
	fake := &fakeLogger{}
	l := NewIdentityLogger(fake, Identity{User: "real", Machine: "real-host"})
	// Caller pre-set a stale identity; the decorator must overwrite it.
	l.Log(Record{RequestID: "r1", User: "stale", Machine: "stale-host"})

	fake.mu.Lock()
	defer fake.mu.Unlock()
	got := fake.records[0]
	if got.User != "real" || got.Machine != "real-host" {
		t.Errorf("identity = %q/%q, want real/real-host (decorator must overwrite)",
			got.User, got.Machine)
	}
}

func TestIdentityLogger_NilInnerIsSafe(t *testing.T) {
	l := NewIdentityLogger(nil, Identity{User: "alice"})
	// Must not panic.
	l.Log(Record{RequestID: "r1"})
	l.Event(Event{Kind: "policy_reload"})
}
