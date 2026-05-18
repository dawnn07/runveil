package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"railcore/internal/ca"
	"railcore/internal/pipeline"
	"railcore/internal/policy"
	"railcore/internal/proxy"
	"railcore/internal/stage/pathscan"
	"railcore/internal/stage/secretscan"
	"railcore/internal/trust"
)

func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	port := fs.Int("port", defaultPort(), "TCP port to listen on (overrides RAILCORE_PORT)")
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for CA + state")
	blockOnDetect := fs.Bool("block-on-detect", false, "return 403 on High-severity secret findings (default WARN only). Ignored when a policy file is in effect.")
	policyPath := fs.String("policy", "", "path to a YAML policy file (default: <data-dir>/policy.yaml if it exists)")
	_ = fs.Parse(args)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	caInst, err := ca.GenerateOrLoad(filepath.Join(*dataDir, "ca"))
	if err != nil {
		logger.Error("ca init failed", "err", err.Error())
		os.Exit(1)
	}

	if err := trust.New().Install(caInst.RootPath()); err != nil {
		logger.Warn("trust-store auto-install did not complete",
			"err", err.Error(),
			"manual_steps", trust.ManualInstructions(caInst.RootPath()))
	}

	loadedPolicy, policyMode, resolvedPath := resolvePolicy(*policyPath, *dataDir, logger)

	effectiveBlock := *blockOnDetect || os.Getenv("RAILCORE_BLOCK_ON_DETECT") == "1"
	if loadedPolicy != nil && effectiveBlock {
		logger.Warn("--block-on-detect ignored because a policy file is in effect",
			"policy_path", resolvedPath)
	}

	chain := pipeline.NewChain().WithLogger(logger)
	chain.Register(pathscan.New(pathscan.Config{Policy: loadedPolicy}, logger))
	chain.Register(secretscan.New(secretscan.Config{
		BlockOnDetect: effectiveBlock,
		Policy:        loadedPolicy,
	}, logger))

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	srv := proxy.New(proxy.Config{
		Addr:     addr,
		CA:       caInst,
		Pipeline: chain,
		Logger:   logger,
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("listen failed", "addr", addr, "err", err.Error())
		fmt.Fprintf(os.Stderr, "port %d in use; set RAILCORE_PORT or stop other process\n", *port)
		os.Exit(1)
	}

	startupArgs := []any{
		"addr", addr,
		"ca_path", caInst.RootPath(),
		"policy_mode", policyMode,
		"block_on_detect", effectiveBlock,
	}
	if resolvedPath != "" {
		startupArgs = append(startupArgs, "policy_path", resolvedPath, "rules", len(loadedPolicy.Rules))
	}
	logger.Info("railcore proxy listening", startupArgs...)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	if err := srv.Serve(ctx, ln); err != nil {
		logger.Error("serve failed", "err", err.Error())
		os.Exit(1)
	}
}

func resolvePolicy(flagPath, dataDir string, logger *slog.Logger) (*policy.Policy, string, string) {
	if flagPath != "" {
		p, err := policy.LoadFromFile(flagPath)
		if err != nil {
			logger.Error("policy load failed (--policy)", "path", flagPath, "err", err.Error())
			os.Exit(1)
		}
		return p, "file", flagPath
	}

	defaultPath := filepath.Join(dataDir, "policy.yaml")
	if _, err := os.Stat(defaultPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "flag", ""
		}
		logger.Error("policy stat failed", "path", defaultPath, "err", err.Error())
		os.Exit(1)
	}

	p, err := policy.LoadFromFile(defaultPath)
	if err != nil {
		logger.Error("policy load failed (default path)", "path", defaultPath, "err", err.Error())
		os.Exit(1)
	}
	return p, "file", defaultPath
}
