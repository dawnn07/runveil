package trust

import (
	"errors"
	"testing"
)

func TestNew_ReturnsNonNilInstaller(t *testing.T) {
	i := New()
	if i == nil {
		t.Fatal("New() returned nil")
	}
}

func TestErrNeedsManual_HasMessage(t *testing.T) {
	if !errors.Is(ErrNeedsManual, ErrNeedsManual) {
		t.Fatal("ErrNeedsManual does not satisfy errors.Is on itself")
	}
	if ErrNeedsManual.Error() == "" {
		t.Fatal("ErrNeedsManual has empty message")
	}
}

func TestManualInstructions_NonEmpty(t *testing.T) {
	// Whichever platform we're on, ManualInstructions must return a
	// non-empty string suitable for printing to the user.
	got := ManualInstructions("/some/path/ca.crt")
	if got == "" {
		t.Fatal("ManualInstructions returned empty string")
	}
}
