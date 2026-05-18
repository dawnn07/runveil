package main

import (
	"net"
	"testing"
)

func TestProxyRunning_Live(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	if !proxyRunning(ln.Addr().String()) {
		t.Errorf("proxyRunning should return true for a bound listener")
	}
}

func TestProxyRunning_Dead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if proxyRunning(addr) {
		t.Errorf("proxyRunning should return false for an unbound address")
	}
}
