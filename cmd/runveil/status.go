package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"runveil/internal/policy"
)

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for CA + state")
	port := fs.Int("port", defaultPort(), "TCP port to probe for a running proxy")
	_ = fs.Parse(args)

	caPath := filepath.Join(*dataDir, "ca", "ca.crt")
	caExists := fileExists(caPath)

	policyPath := filepath.Join(*dataDir, "policy.yaml")
	policyExists := fileExists(policyPath)
	policyParses, policyMsg, ruleCount := checkPolicy(policyPath, policyExists)

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	running := proxyRunning(addr)

	fmt.Println("runveil status")
	fmt.Println()
	fmt.Println("CA:")
	fmt.Printf("  path:        %s\n", caPath)
	fmt.Printf("  exists:      %s\n", yesNo(caExists))
	fmt.Println()
	fmt.Println("Policy:")
	fmt.Printf("  path:        %s\n", policyPath)
	fmt.Printf("  exists:      %s\n", yesNo(policyExists))
	if policyExists {
		if policyParses {
			fmt.Printf("  parses:      yes (%d rules)\n", ruleCount)
		} else {
			fmt.Printf("  parses:      no (%s)\n", policyMsg)
		}
	}
	fmt.Println()
	fmt.Println("Proxy:")
	fmt.Printf("  port:        %d\n", *port)
	fmt.Printf("  running:     %s\n", yesNo(running))

	if !caExists {
		fmt.Println()
		fmt.Println("Run 'runveil init' first.")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func checkPolicy(path string, exists bool) (parses bool, errMsg string, ruleCount int) {
	if !exists {
		return false, "", 0
	}
	p, err := policy.LoadFromFile(path)
	if err != nil {
		return false, err.Error(), 0
	}
	return true, "", len(p.Rules)
}

func proxyRunning(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
