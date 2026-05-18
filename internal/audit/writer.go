package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Config configures a Writer. Path and MaxSizeMB are required; the
// remaining fields fall back to sensible defaults when zero.
type Config struct {
	Path       string // file path; required (caller passes "" to opt out at a higher layer)
	MaxSizeMB  int    // before rotation; required (> 0)
	MaxBackups int    // rotated files to keep; default 5
	MaxAgeDays int    // total age cap; default 30
	BufferSize int    // channel buffer; default 1024
}

// Writer is the lumberjack-backed, async, file-writing Logger.
type Writer struct {
	logger    *slog.Logger
	ch        chan Record
	done      chan struct{}
	wg        sync.WaitGroup
	lj        *lumberjack.Logger
	closed    atomic.Bool
	closeOnce sync.Once
}

// NewWriter probes that Path is writable, opens the lumberjack writer,
// starts the background goroutine, and returns a *Writer. Returns an
// error if the path is empty, MaxSizeMB <= 0, or the path is
// unwritable.
func NewWriter(cfg Config, logger *slog.Logger) (*Writer, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("audit: Path is required")
	}
	if cfg.MaxSizeMB <= 0 {
		return nil, fmt.Errorf("audit: MaxSizeMB must be > 0")
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 5
	}
	if cfg.MaxAgeDays <= 0 {
		cfg.MaxAgeDays = 30
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 1024
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: create parent dir: %w", err)
	}

	// Probe writability: try opening the file for append.
	probe, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", cfg.Path, err)
	}
	_ = probe.Close()

	lj := &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSizeMB,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAgeDays,
		LocalTime:  false,
		Compress:   false,
	}

	w := &Writer{
		logger: logger,
		ch:     make(chan Record, cfg.BufferSize),
		lj:     lj,
		done:   make(chan struct{}),
	}
	w.wg.Add(1)
	go w.run()
	return w, nil
}

// Log implements Logger. Non-blocking: drops the record (with a WARN
// to the slog logger) if the channel is full.
//
// Safe to call after Close: silently does nothing.
func (w *Writer) Log(r Record) {
	if w == nil || w.closed.Load() {
		return
	}
	select {
	case w.ch <- r:
		// queued
	default:
		w.logger.Warn("audit channel full; dropping record",
			"request_id", r.RequestID)
	}
}

// Close drains the buffer, flushes lumberjack, stops the goroutine.
// Idempotent. After Close, Log is a no-op.
//
// We never close w.ch — closing it would race concurrent Log calls and
// cause "send on closed channel" panics. Instead we signal shutdown via
// the done channel and let the run goroutine drain remaining records.
func (w *Writer) Close() error {
	var err error
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		close(w.done)
		w.wg.Wait()
		err = w.lj.Close()
	})
	return err
}

// run is the background goroutine. Reads records from the channel
// until done is signaled, then drains any remaining buffered records
// (non-blocking) and exits.
func (w *Writer) run() {
	defer w.wg.Done()
	var buf bytes.Buffer
	for {
		select {
		case r := <-w.ch:
			w.writeRecord(&buf, r)
		case <-w.done:
			// Drain any remaining buffered records without blocking.
			for {
				select {
				case r := <-w.ch:
					w.writeRecord(&buf, r)
				default:
					return
				}
			}
		}
	}
}

func (w *Writer) writeRecord(buf *bytes.Buffer, r Record) {
	buf.Reset()
	if err := json.NewEncoder(buf).Encode(r); err != nil {
		w.logger.Error("audit: marshal record",
			"request_id", r.RequestID,
			"err", err.Error())
		return
	}
	if _, err := w.lj.Write(buf.Bytes()); err != nil {
		w.logger.Error("audit: write",
			"err", err.Error())
	}
}
