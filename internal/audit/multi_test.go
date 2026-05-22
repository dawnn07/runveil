package audit

import (
	"sync"
	"testing"
	"time"
)

// fakeLogger is a Logger that records every call, guarded by a mutex.
type fakeLogger struct {
	mu      sync.Mutex
	records []Record
	events  []Event
}

func (f *fakeLogger) Log(r Record) {
	f.mu.Lock()
	f.records = append(f.records, r)
	f.mu.Unlock()
}

func (f *fakeLogger) Event(e Event) {
	f.mu.Lock()
	f.events = append(f.events, e)
	f.mu.Unlock()
}

func (f *fakeLogger) recordCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.records)
}

func (f *fakeLogger) eventCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

func TestMultiLogger_ForwardsLogToAll(t *testing.T) {
	a, b := &fakeLogger{}, &fakeLogger{}
	m := NewMultiLogger(a, b)
	m.Log(Record{Time: time.Now(), RequestID: "r1"})
	if a.recordCount() != 1 || b.recordCount() != 1 {
		t.Errorf("record counts = %d/%d, want 1/1", a.recordCount(), b.recordCount())
	}
}

func TestMultiLogger_ForwardsEventToAll(t *testing.T) {
	a, b := &fakeLogger{}, &fakeLogger{}
	m := NewMultiLogger(a, b)
	m.Event(Event{Time: time.Now(), Kind: "policy_reload"})
	if a.eventCount() != 1 || b.eventCount() != 1 {
		t.Errorf("event counts = %d/%d, want 1/1", a.eventCount(), b.eventCount())
	}
}

func TestMultiLogger_SkipsNilLoggers(t *testing.T) {
	a := &fakeLogger{}
	m := NewMultiLogger(a, nil)
	m.Log(Record{RequestID: "r1"}) // must not panic
	m.Event(Event{Kind: "x"})      // must not panic
	if a.recordCount() != 1 || a.eventCount() != 1 {
		t.Errorf("non-nil logger should still receive calls; got %d/%d",
			a.recordCount(), a.eventCount())
	}
}

func TestMultiLogger_ZeroLoggersIsNoop(t *testing.T) {
	m := NewMultiLogger()
	// Must not panic with no wrapped loggers.
	m.Log(Record{RequestID: "r1"})
	m.Event(Event{Kind: "x"})
}
