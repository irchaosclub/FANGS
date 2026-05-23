// SPDX-License-Identifier: Apache-2.0
//
// Package metrics owns the Prometheus instrumentation surface of the
// FANGS orchestrator. Every metric is registered once at process start
// and read off by promhttp at /metrics on the same listen address.
//
// Design rules:
//   - Counters only increment, never reset. Restarting the orchestrator
//     resets them — that's documented Prometheus behavior and the
//     scraper handles it via `rate()`.
//   - Gauges are populated by a "scrape collector" so they reflect
//     current DB state instead of staleness from in-memory snapshots.
//   - Cardinality stays modest: labels are bounded enumerations
//     (severity, event type, status), never user-controlled strings.
//
// Per D42: localhost-bound by default (inherited from the
// orchestrator's -addr); operators behind a reverse proxy can expose
// it intentionally.
package metrics

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

// Registry holds the registered metrics. Constructed once by main and
// passed to the api.Server + differ + notifier for incrementing.
type Registry struct {
	reg *prometheus.Registry

	OrchestratorInfo  *prometheus.GaugeVec
	EventsReceived    *prometheus.CounterVec
	EventsDropped     prometheus.Counter
	ScansQueued       prometheus.Counter
	DeviationsWritten *prometheus.CounterVec
	BaselinePromoted  *prometheus.CounterVec
	NotificationsSent *prometheus.CounterVec
	RunnersRegistered prometheus.GaugeFunc
}

// Options controls dynamic gauges that need to reach back into the
// orchestrator for their values at scrape time.
type Options struct {
	Version       string
	RunnersFn     func() int            // current registered-runner count
	RunsByStateFn func() map[string]int // optional gauge of run states
	Logger        *slog.Logger
}

// New constructs and registers a Registry.
func New(opts Options) *Registry {
	reg := prometheus.NewRegistry()
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	r := &Registry{reg: reg}

	r.OrchestratorInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fangs_orchestrator_info",
		Help: "Build / version info. Always 1; carries labels for the build identity.",
	}, []string{"version"})
	r.OrchestratorInfo.WithLabelValues(opts.Version).Set(1)

	r.EventsReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fangs_events_received_total",
		Help: "Sensor events received by the orchestrator, by event type.",
	}, []string{"type"})

	r.ScansQueued = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fangs_scans_queued_total",
		Help: "Number of sandbox scans queued onto a runner.",
	})

	r.EventsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fangs_events_dropped_total",
		Help: "Sensor events dropped because the in-kernel ringbuf was full. Reported by the runner in ScanResult; rate > 0 indicates a too-small ringbuf or too-slow consumer.",
	})

	r.DeviationsWritten = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fangs_deviations_written_total",
		Help: "Deviations emitted by the Differ, by severity.",
	}, []string{"severity"})

	r.BaselinePromoted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fangs_baseline_promoted_total",
		Help: "Runs promoted into baseline, by trigger (auto = D38 zero-deviation, manual = CLI promote).",
	}, []string{"trigger"})

	r.NotificationsSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fangs_notifications_total",
		Help: "Notifier delivery attempts, by notifier name + final status.",
	}, []string{"notifier", "status"})

	if opts.RunnersFn != nil {
		r.RunnersRegistered = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fangs_runners_registered",
			Help: "Currently-registered runners (heartbeat-fresh; pruner-evicted runners are not counted).",
		}, func() float64 { return float64(opts.RunnersFn()) })
	}

	for _, c := range []prometheus.Collector{
		r.OrchestratorInfo,
		r.EventsReceived,
		r.EventsDropped,
		r.ScansQueued,
		r.DeviationsWritten,
		r.BaselinePromoted,
		r.NotificationsSent,
	} {
		reg.MustRegister(c)
	}
	if r.RunnersRegistered != nil {
		reg.MustRegister(r.RunnersRegistered)
	}

	// Add the runtime collectors so we get goroutines / GC / memory by
	// default. Useful for ops dashboards without extra wiring.
	reg.MustRegister(prometheus.NewGoCollector())
	reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	return r
}

// Mount installs the /metrics endpoint on mux.
func (r *Registry) Mount(mux *http.ServeMux) {
	mux.Handle("GET /metrics", promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{}))
}

// ObserveScanQueued is a no-op-safe convenience for call sites that
// hold a possibly-nil Registry.
func (r *Registry) ObserveScanQueued() {
	if r == nil {
		return
	}
	r.ScansQueued.Inc()
}

// ObserveEvent — increment per-type event counter.
func (r *Registry) ObserveEvent(eventType string, n int) {
	if r == nil {
		return
	}
	r.EventsReceived.WithLabelValues(eventType).Add(float64(n))
}

// ObserveEventsDropped — bump the lifetime drop counter by n. Called
// once per ScanResult arrival.
func (r *Registry) ObserveEventsDropped(n int64) {
	if r == nil || n <= 0 {
		return
	}
	r.EventsDropped.Add(float64(n))
}

// ObserveDeviationsWritten increments the per-severity counter for a
// batch of deviations. The Differ calls this once per AnalyzeRun.
func (r *Registry) ObserveDeviationsWritten(rows []storage.DeviationRow) {
	if r == nil {
		return
	}
	for _, d := range rows {
		sev := d.Severity
		if sev == "" {
			sev = "unknown"
		}
		r.DeviationsWritten.WithLabelValues(sev).Inc()
	}
}

// ObserveBaselinePromoted — trigger is "auto" (D38) or "manual" (CLI).
func (r *Registry) ObserveBaselinePromoted(ctx context.Context, trigger string) {
	if r == nil {
		return
	}
	r.BaselinePromoted.WithLabelValues(trigger).Inc()
}

// ObserveNotification — status is "sent" | "failed" | "permanent".
func (r *Registry) ObserveNotification(notifier, status string) {
	if r == nil {
		return
	}
	r.NotificationsSent.WithLabelValues(notifier, status).Inc()
}
