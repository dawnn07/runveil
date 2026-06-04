package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func defaultPort() int {
	if v := os.Getenv("RUNVEIL_PORT"); v != "" {
		var p int
		if _, err := fmt.Sscanf(v, "%d", &p); err == nil && p > 0 {
			return p
		}
	}
	return 9443
}

func defaultDataDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".runveil")
	}
	return ".runveil-data"
}
