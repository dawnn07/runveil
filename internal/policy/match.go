package policy

// globPattern is filled in by Task 2; this file exists only so policy.go
// compiles standalone.
type globPattern struct{}

func (g *globPattern) match(_ string) bool { return false }
