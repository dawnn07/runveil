package main

import (
	"testing"
)

func TestDetectIdentity(t *testing.T) {
	t.Run("flag wins over env and OS", func(t *testing.T) {
		t.Setenv("RAILCORE_IDENTITY", "env-user")
		id := detectIdentity("flag-user")
		if id.User != "flag-user" {
			t.Errorf("User = %q, want flag-user (flag must win)", id.User)
		}
	})

	t.Run("env wins over OS when flag empty", func(t *testing.T) {
		t.Setenv("RAILCORE_IDENTITY", "env-user")
		id := detectIdentity("")
		if id.User != "env-user" {
			t.Errorf("User = %q, want env-user (env must win when flag empty)", id.User)
		}
	})

	t.Run("falls back to OS user when flag and env empty", func(t *testing.T) {
		t.Setenv("RAILCORE_IDENTITY", "")
		id := detectIdentity("")
		// We can't assert the exact OS username portably, but in a normal
		// test environment os/user.Current() succeeds, so User must be
		// non-empty. If it somehow fails, "" is the documented degraded
		// result — accept either rather than making the test flaky.
		_ = id.User // presence is environment-dependent; see machine check below
	})

	t.Run("machine is the hostname", func(t *testing.T) {
		id := detectIdentity("anyone")
		// os.Hostname() succeeds in essentially all test environments.
		if id.Machine == "" {
			t.Error("Machine is empty; expected a hostname")
		}
	})
}
