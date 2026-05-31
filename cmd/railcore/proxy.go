package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	osuser "os/user"
	"path/filepath"
	"syscall"
	"time"

	"railcore/internal/audit"
	"railcore/internal/ca"
	"railcore/internal/enrollment"
	"railcore/internal/metrics"
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
	auditEnabled := fs.Bool("audit-enabled", true, "write per-request audit records to a JSON Lines log file")
	auditLog := fs.String("audit-log", "", "path to audit log file (default: <data-dir>/audit.log)")
	auditMaxSizeMB := fs.Int("audit-max-size-mb", 100, "max audit file size before rotation")
	auditMaxBackups := fs.Int("audit-max-backups", 5, "rotated audit files to retain")
	auditMaxAgeDays := fs.Int("audit-max-age-days", 30, "max age in days for rotated audit files")
	siemURL := fs.String("siem-url", "", "SIEM collector endpoint URL; empty disables SIEM export")
	siemAuthHeader := fs.String("siem-auth-header", "", "auth header name for SIEM POSTs (value from RAILCORE_SIEM_AUTH env)")
	siemBatchSize := fs.Int("siem-batch-size", 100, "audit records per SIEM batch")
	siemFlushInterval := fs.Duration("siem-flush-interval", 5*time.Second, "max age of a partial SIEM batch")
	siemMaxBufferBatches := fs.Int("siem-max-buffer-batches", 64, "SIEM retry-buffer cap (batches) before drop-oldest")
	identityFlag := fs.String("identity", "",
		"developer identity for audit records (default: OS username; RAILCORE_IDENTITY env also honored)")
	metricsPort := fs.Int("metrics-port", 0,
		"port for the Prometheus /metrics endpoint (0 = disabled; e.g. 9464)")
	policyURL := fs.String("policy-url", "",
		"fetch policy from this HTTP(S) URL instead of a local file (control-plane mode)")
	policyURLInterval := fs.Duration("policy-url-interval", 30*time.Second,
		"how often to poll --policy-url for changes")
	policyURLAuthHeader := fs.String("policy-url-auth-header", "",
		"auth header name for --policy-url requests (value from RAILCORE_POLICY_TOKEN env)")
	upstreamOverride := fs.String("upstream-override", os.Getenv("RAILCORE_UPSTREAM_OVERRIDE"),
		"redirect every upstream TLS dial to this host:port (test/staging only; overrides RAILCORE_UPSTREAM_OVERRIDE)")
	upstreamCA := fs.String("upstream-ca", os.Getenv("RAILCORE_UPSTREAM_CA"),
		"PEM file to trust as the only upstream root CA (test/staging only; overrides RAILCORE_UPSTREAM_CA)")
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

	enr, err := enrollment.Load(*dataDir)
	if err != nil {
		logger.Error("enrollment load failed", "err", err.Error())
		os.Exit(1)
	}
	logger.Info("audit enrollment", "org_id", enr.OrgID, "enrolled", !enr.IsZero())

	// Resolve audit log path.
	auditPath := *auditLog
	if auditPath == "" {
		auditPath = filepath.Join(*dataDir, "audit.log")
	}

	var auditWriter *audit.Writer
	if *auditEnabled {
		w, err := audit.NewWriter(audit.Config{
			Path:       auditPath,
			MaxSizeMB:  *auditMaxSizeMB,
			MaxBackups: *auditMaxBackups,
			MaxAgeDays: *auditMaxAgeDays,
		}, logger)
		if err != nil {
			logger.Error("audit init failed", "err", err.Error())
			os.Exit(1)
		}
		auditWriter = w
		defer func() { _ = auditWriter.Close() }()
	}

	// Construct the SIEM sink when --siem-url is set.
	var siemSink *audit.HTTPSink
	if *siemURL != "" {
		if *siemAuthHeader != "" && os.Getenv("RAILCORE_SIEM_AUTH") == "" {
			logger.Warn("siem auth header configured but RAILCORE_SIEM_AUTH is empty")
		}
		sink, err := audit.NewHTTPSink(audit.HTTPConfig{
			URL:              *siemURL,
			AuthHeader:       *siemAuthHeader,
			AuthValue:        os.Getenv("RAILCORE_SIEM_AUTH"),
			BatchSize:        *siemBatchSize,
			FlushInterval:    *siemFlushInterval,
			MaxBufferBatches: *siemMaxBufferBatches,
		}, logger)
		if err != nil {
			logger.Error("siem sink init failed", "err", err.Error())
			os.Exit(1)
		}
		siemSink = sink
		defer func() { _ = siemSink.Close() }()
	}

	// Assemble the effective audit logger from the live sinks.
	var metricsCollector *metrics.Collector
	if *metricsPort != 0 {
		metricsCollector = metrics.NewCollector()
	}

	var auditLogger audit.Logger = audit.NoopLogger{}
	var sinks []audit.Logger
	if auditWriter != nil {
		sinks = append(sinks, auditWriter)
	}
	if siemSink != nil {
		sinks = append(sinks, siemSink)
	}
	if metricsCollector != nil {
		sinks = append(sinks, metricsCollector)
	}
	switch len(sinks) {
	case 0:
		// auditLogger stays NoopLogger
	case 1:
		auditLogger = sinks[0]
	default:
		auditLogger = audit.NewMultiLogger(sinks...)
	}

	// Stamp every record/event with the developer identity. Wrapping is
	// unconditional — even a NoopLogger gets wrapped harmlessly. This
	// must happen before the policy watcher is built, since the
	// watcher's callbacks capture auditLogger.
	identity := detectIdentity(*identityFlag)
	identity.OrgID = enr.OrgID
	auditLogger = audit.NewIdentityLogger(auditLogger, identity)
	logger.Info("audit identity", "user", identity.User, "machine", identity.Machine, "org_id", identity.OrgID)

	// --- Policy source selection: local file (default) or remote URL. ---
	if *policyURL != "" && *policyPath != "" {
		logger.Error("--policy and --policy-url are mutually exclusive; choose one source")
		os.Exit(1)
	}

	effectiveBlock := *blockOnDetect || os.Getenv("RAILCORE_BLOCK_ON_DETECT") == "1"

	chain := pipeline.NewChain().WithLogger(logger)

	// policies holds the live policy; policyMode/policySource describe
	// where it came from (for the startup log and reload events).
	var policies *policy.Provider
	var policyMode string
	var policySource string

	// Shared reload callbacks for whichever source is active. They
	// capture `policies` and `policySource`; both are assigned before
	// any source's poll/watch goroutine is started.
	onAccept := func(np *policy.Policy) {
		before := policies.Get().RuleCount()
		policies.Set(np)
		auditLogger.Event(audit.Event{
			Time:        time.Now(),
			Kind:        "policy_reload",
			PolicyPath:  policySource,
			Outcome:     "accepted",
			RulesBefore: before,
			RulesAfter:  np.RuleCount(),
		})
		logger.Info("policy reloaded", "source", policySource,
			"rules_before", before, "rules_after", np.RuleCount())
	}
	onReject := func(rerr error, _ []byte) {
		before := policies.Get().RuleCount()
		auditLogger.Event(audit.Event{
			Time:        time.Now(),
			Kind:        "policy_reload",
			PolicyPath:  policySource,
			Outcome:     "rejected",
			RulesBefore: before,
			Error:       rerr.Error(),
		})
		logger.Warn("policy reload rejected", "source", policySource, "err", rerr.Error())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if metricsCollector != nil {
		metricsAddr := fmt.Sprintf("127.0.0.1:%d", *metricsPort)
		mux := http.NewServeMux()
		mux.Handle("/metrics", metricsCollector.Handler())
		metricsSrv := &http.Server{Addr: metricsAddr, Handler: mux}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("metrics server failed", "err", err.Error())
			}
		}()
		defer func() { _ = metricsSrv.Close() }()
		logger.Info("metrics endpoint listening", "addr", metricsAddr, "path", "/metrics")
	}

	if *policyURL != "" {
		// --- Remote mode: fetch policy from the URL, poll for updates. ---
		policyMode = "url"
		policySource = *policyURL
		cachePath := filepath.Join(*dataDir, "policy-cache.yaml")

		// Auth value precedence: RAILCORE_POLICY_TOKEN (per-endpoint
		// override) wins; otherwise fall back to the enrollment device
		// token; otherwise empty (no auth header is sent).
		authValue := os.Getenv("RAILCORE_POLICY_TOKEN")
		if authValue == "" {
			authValue = enr.DeviceToken
		} else if enr.DeviceToken != "" {
			logger.Debug("RAILCORE_POLICY_TOKEN overrides device token for policy URL")
		}
		if *policyURLAuthHeader != "" && authValue == "" {
			logger.Warn("policy URL auth header configured but no token available (set RAILCORE_ORG_ID + RAILCORE_DEVICE_TOKEN, enroll via device.json, or set RAILCORE_POLICY_TOKEN)")
		}
		src, serr := policy.NewRemoteSource(policy.RemoteConfig{
			URL:        *policyURL,
			AuthHeader: *policyURLAuthHeader,
			AuthValue:  authValue,
			Interval:   *policyURLInterval,
			CachePath:  cachePath,
		}, logger, onAccept, onReject)
		if serr != nil {
			logger.Error("policy URL invalid", "err", serr.Error())
			os.Exit(1)
		}
		initial, ferr := src.Fetch()
		if ferr != nil {
			cached, cerr := policy.LoadFromFile(cachePath)
			if cerr != nil {
				logger.Error("policy URL unreachable and no cache available",
					"url", *policyURL, "cache", cachePath,
					"url_err", ferr.Error(), "cache_err", cerr.Error())
				os.Exit(1)
			}
			initial = cached
			logger.Warn("policy URL unreachable at startup; loaded cached policy",
				"url", *policyURL, "cache", cachePath, "err", ferr.Error())
		} else {
			logger.Info("policy loaded from URL", "url", *policyURL, "rules", initial.RuleCount())
		}
		policies = policy.NewProvider(initial)
		if err := src.Start(ctx); err != nil {
			logger.Error("policy poller start failed", "err", err.Error())
			os.Exit(1)
		}
		defer func() { _ = src.Close() }()
	} else {
		// --- File mode: load the policy file, watch it for changes. ---
		loadedPolicy, mode, resolvedPath := resolvePolicy(*policyPath, *dataDir, logger)
		policyMode = mode
		policySource = resolvedPath
		policies = policy.NewProvider(loadedPolicy)
		if loadedPolicy != nil && effectiveBlock {
			logger.Warn("--block-on-detect ignored because a policy file is in effect",
				"policy_path", resolvedPath)
		}
		if resolvedPath != "" {
			watcher, werr := policy.NewWatcher(resolvedPath, logger, onAccept, onReject)
			if werr != nil {
				logger.Error("policy watcher init failed", "err", werr.Error())
				os.Exit(1)
			}
			if werr := watcher.Start(ctx); werr != nil {
				logger.Error("policy watcher start failed", "err", werr.Error())
				os.Exit(1)
			}
			defer func() { _ = watcher.Close() }()
		}
	}

	chain.Register(pathscan.New(pathscan.Config{Policies: policies}, logger))
	chain.Register(secretscan.New(secretscan.Config{
		BlockOnDetect: effectiveBlock,
		Policies:      policies,
	}, logger))

	// --upstream-ca alone (without --upstream-override) would silently
	// narrow upstream TLS trust to just the supplied PEM for all dials,
	// breaking production handshakes to real vendor hosts. The flag pair
	// is documented as "test/staging only" — require them together.
	if *upstreamCA != "" && *upstreamOverride == "" {
		logger.Error("--upstream-ca requires --upstream-override (test/staging mode pairs both flags)")
		os.Exit(1)
	}

	var upstreamResolver func(string) (string, error)
	if *upstreamOverride != "" {
		if _, _, err := net.SplitHostPort(*upstreamOverride); err != nil {
			logger.Error("invalid --upstream-override", "value", *upstreamOverride, "err", err.Error())
			os.Exit(1)
		}
		target := *upstreamOverride
		upstreamResolver = func(string) (string, error) { return target, nil }
	}

	var upstreamTLS *tls.Config
	if *upstreamCA != "" {
		pem, err := os.ReadFile(*upstreamCA)
		if err != nil {
			logger.Error("upstream CA read failed", "path", *upstreamCA, "err", err.Error())
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			logger.Error("upstream CA file contained no valid PEM certificates", "path", *upstreamCA)
			os.Exit(1)
		}
		upstreamTLS = &tls.Config{RootCAs: pool}
	}

	if upstreamResolver != nil || upstreamTLS != nil {
		logger.Warn("upstream override active (test/staging mode)",
			"override", *upstreamOverride, "ca", *upstreamCA)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	srv := proxy.New(proxy.Config{
		Addr:             addr,
		CA:               caInst,
		Pipeline:         chain,
		Logger:           logger,
		AuditFunc:        auditLogger,
		UpstreamResolver: upstreamResolver,
		UpstreamTLS:      upstreamTLS,
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
	if policySource != "" {
		startupArgs = append(startupArgs, "policy_source", policySource,
			"rules", policies.Get().RuleCount())
	}
	logger.Info("railcore proxy listening", startupArgs...)

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

// detectIdentity resolves the developer identity stamped onto audit
// records. Precedence for the user: --identity flag, then the
// RAILCORE_IDENTITY env var, then the OS username. machine is always
// the hostname. Any source may fail to a "" value, which is dropped
// from the audit record by omitempty.
func detectIdentity(flagVal string) audit.Identity {
	name := flagVal
	if name == "" {
		name = os.Getenv("RAILCORE_IDENTITY")
	}
	if name == "" {
		if u, err := osuser.Current(); err == nil {
			name = u.Username
		}
	}
	machine, _ := os.Hostname()
	return audit.Identity{User: name, Machine: machine}
}
