package policy

import (
	"sync"
	"testing"
)

func TestProvider_GetReturnsStoredPointer(t *testing.T) {
	p := &Policy{Version: 1}
	pr := NewProvider(p)
	got := pr.Get()
	if got != p {
		t.Errorf("Get() = %v, want %v", got, p)
	}
}

func TestProvider_NilSafe(t *testing.T) {
	pr := NewProvider(nil)
	if pr.Get() != nil {
		t.Errorf("Get() on nil Provider must return nil")
	}
}

func TestProvider_SetSwapsAtomically(t *testing.T) {
	pr := NewProvider(&Policy{Version: 1})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = pr.Get()
				}
			}
		}()
	}

	for i := 0; i < 1000; i++ {
		pr.Set(&Policy{Version: i + 2})
	}
	close(stop)
	wg.Wait()
}
