package audit

// Identity is the developer attribution stamped onto audit records and
// events. Captured once at proxy startup; constant for the process.
type Identity struct {
	User    string // developer identity — OS username or a configured override
	Machine string // hostname
	OrgID   string // control-plane org id from enrollment ("" when unenrolled)
}

// IdentityLogger decorates a Logger, stamping a fixed Identity onto
// every Record and Event before forwarding to the inner logger.
//
// Like MultiLogger, IdentityLogger does not own lifecycle: it has no
// Close method. The caller holds the concrete sinks and closes them
// directly.
type IdentityLogger struct {
	inner    Logger
	identity Identity
}

// NewIdentityLogger wraps inner so every Log/Event call carries the
// given identity. A nil inner makes all calls no-ops.
func NewIdentityLogger(inner Logger, id Identity) *IdentityLogger {
	return &IdentityLogger{inner: inner, identity: id}
}

// Log stamps the identity onto r and forwards to the inner logger.
// The stamp is an unconditional overwrite — the decorator is the sole
// authority on identity.
func (l *IdentityLogger) Log(r Record) {
	if l.inner == nil {
		return
	}
	r.User = l.identity.User
	r.Machine = l.identity.Machine
	r.OrgID = l.identity.OrgID
	l.inner.Log(r)
}

// Event stamps the identity onto e and forwards to the inner logger.
func (l *IdentityLogger) Event(e Event) {
	if l.inner == nil {
		return
	}
	e.User = l.identity.User
	e.Machine = l.identity.Machine
	e.OrgID = l.identity.OrgID
	l.inner.Event(e)
}
