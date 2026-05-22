// Package metrics translates the Railcore audit Record/Event stream
// into Prometheus metrics and serves them on a /metrics endpoint.
//
// The Collector implements audit.Logger so it joins the audit
// MultiLogger fan-out — every request and event is observed with no
// hot-path wiring. metrics depends on internal/audit (for the Record /
// Event / Logger types) and prometheus/client_golang.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"railcore/internal/audit"
)

// Compile-time guarantee that *Collector is a valid audit sink.
var _ audit.Logger = (*Collector)(nil)

// Collector observes the audit stream and exposes Prometheus metrics.
// It owns a private registry so the metric set is explicit and tests
// are fully isolated.
//
// Like the other audit decorators/sinks, Collector owns no goroutine or
// resource and has no Close method.
type Collector struct {
	registry *prometheus.Registry

	requests *prometheus.CounterVec // label: decision
	duration prometheus.Histogram
	bytesIn  prometheus.Counter
	bytesOut prometheus.Counter
	findings *prometheus.CounterVec // label: detector
	reloads  *prometheus.CounterVec // label: outcome
}

// NewCollector builds a Collector with a fresh private registry holding
// the six application metrics plus the Go-runtime and process
// collectors.
func NewCollector() *Collector {
	c := &Collector{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "railcore_requests_total",
			Help: "Total AI requests by pipeline decision.",
		}, []string{"decision"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "railcore_request_duration_seconds",
			Help:    "Wall-clock AI request duration in seconds.",
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		}),
		bytesIn: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "railcore_request_bytes_in_total",
			Help: "Total request bytes inspected.",
		}),
		bytesOut: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "railcore_request_bytes_out_total",
			Help: "Total response bytes streamed back.",
		}),
		findings: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "railcore_findings_total",
			Help: "Detector findings by detector type.",
		}, []string{"detector"}),
		reloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "railcore_policy_reloads_total",
			Help: "Policy reload attempts by outcome.",
		}, []string{"outcome"}),
	}
	c.registry.MustRegister(
		c.requests,
		c.duration,
		c.bytesIn,
		c.bytesOut,
		c.findings,
		c.reloads,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return c
}

// Log implements audit.Logger: it records one request's metrics.
func (c *Collector) Log(r audit.Record) {
	c.requests.WithLabelValues(r.Decision).Inc()
	c.duration.Observe(float64(r.DurationMs) / 1000.0)
	c.bytesIn.Add(float64(r.BytesIn))
	c.bytesOut.Add(float64(r.BytesOut))
	for _, f := range r.Findings {
		m, ok := f.(map[string]any)
		if !ok {
			continue
		}
		if det, ok := m["detector"].(string); ok && det != "" {
			c.findings.WithLabelValues(det).Inc()
		}
	}
}

// Event implements audit.Logger: it records policy-reload outcomes.
// Other event kinds are ignored.
func (c *Collector) Event(e audit.Event) {
	if e.Kind == "policy_reload" {
		c.reloads.WithLabelValues(e.Outcome).Inc()
	}
}

// Handler returns the HTTP handler for the /metrics endpoint.
func (c *Collector) Handler() http.Handler {
	return promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{})
}
