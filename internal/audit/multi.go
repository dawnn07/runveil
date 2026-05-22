package audit

// MultiLogger forwards every Log and Event call to each wrapped Logger,
// in order. Used to tee audit output to the file Writer and the HTTP
// SIEM sink.
//
// MultiLogger does not own lifecycle: it has no Close method. Callers
// hold direct references to the concrete sinks and close them
// individually.
type MultiLogger struct {
	loggers []Logger
}

// NewMultiLogger returns a MultiLogger fanning out to the given loggers.
// nil entries are skipped. With zero non-nil loggers it behaves as a
// no-op.
func NewMultiLogger(loggers ...Logger) *MultiLogger {
	var nonNil []Logger
	for _, l := range loggers {
		if l != nil {
			nonNil = append(nonNil, l)
		}
	}
	return &MultiLogger{loggers: nonNil}
}

// Log implements Logger by forwarding to each wrapped logger in order.
func (m *MultiLogger) Log(r Record) {
	for _, l := range m.loggers {
		l.Log(r)
	}
}

// Event implements Logger by forwarding to each wrapped logger in order.
func (m *MultiLogger) Event(e Event) {
	for _, l := range m.loggers {
		l.Event(e)
	}
}
