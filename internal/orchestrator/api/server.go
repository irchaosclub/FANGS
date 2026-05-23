// SPDX-License-Identifier: Apache-2.0
//
// Package api implements the orchestrator-side HTTPS surface that runners
// connect to. v1 endpoints:
//
//	GET  /v1/health
//	POST /v1/runners/register
//	GET  /v1/runners/{id}/jobs        (long-poll; 204 when no work)
//	POST /v1/runs/{run_id}/events     (chunked stream of EventBatch)
//	POST /v1/runs/{run_id}/result
//
// This file lands the skeleton + the first two endpoints. Job dispatch
// and event ingest land in follow-up commits.
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/core"
	"github.com/irchaosclub/FANGS/internal/orchestrator/differ"
	"github.com/irchaosclub/FANGS/internal/orchestrator/notifier"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

// Server is the orchestrator's HTTP front-end. Constructed via New, started
// via Serve(ctx), shut down via Shutdown.
type Server struct {
	addr           string
	orchestratorID string
	version        string
	logger         *slog.Logger
	dispatcher     *core.Dispatcher
	store          storage.Backend
	differ         *differ.Differ
	notifier       *notifier.Notifier

	tlsCertFile     string
	tlsKeyFile      string
	tlsClientCAFile string

	// defaultWatchedPaths is the set the orchestrator stamps onto every
	// incoming job whose WatchedPaths is empty. Loaded from config at
	// startup (config.Config.WatchedPathsAsProto). Allows operators to
	// edit one place and have it apply to every scan, manual or
	// autonomous.
	defaultWatchedPaths []proto.WatchedPath

	metrics metricsSink

	mu      sync.Mutex
	runners map[string]registeredRunner // runner_id -> registration record

	// differMu guards differTimers. Per-run debounce: each event-batch
	// POST schedules (or resets) a 2s timer; when it fires we run the
	// Differ once. Avoids running Differ N times for an N-batch stream.
	differMu     sync.Mutex
	differTimers map[string]*time.Timer
}

// metricsSink is the minimal contract the api package needs from the
// metrics package. Defining it here keeps api free of the prometheus
// dependency (the orchestrator main wires a concrete *metrics.Registry).
type metricsSink interface {
	ObserveScanQueued()
	ObserveEvent(eventType string, n int)
	ObserveEventsDropped(n int64)
	ObserveDeviationsWritten(rows []storage.DeviationRow)
}

// SetMetrics installs the metrics sink. Safe to call before or after
// Serve; nil sink disables instrumentation gracefully. Also forwards
// the sink to the Differ (the only other internal consumer).
func (s *Server) SetMetrics(m metricsSink) {
	s.metrics = m
	if s.differ != nil {
		// Type-asserting through the interface keeps differ free of the
		// metrics import while still letting it observe.
		if md, ok := m.(differMetricsSink); ok {
			s.differ.SetMetrics(md)
		}
	}
}

// differMetricsSink is the subset of metricsSink the differ needs.
// Defining it here lets us hand the differ exactly what it asked for
// without it having to know the wider API.
type differMetricsSink interface {
	ObserveDeviationsWritten(rows []storage.DeviationRow)
}

type registeredRunner struct {
	Registration proto.RunnerRegistration
	RegisteredAt time.Time
	LastSeen     time.Time
	ActiveRunID  string // hex; "" when idle
	Status       string // last-reported status from a heartbeat
	EventsQueued int    // last-reported runner-side queue depth
}

// Options configures a Server.
type Options struct {
	Addr           string // listen address, e.g. "127.0.0.1:8443"
	OrchestratorID string // identifies this orchestrator in handshakes
	Version        string // build-info string for /v1/health
	Logger         *slog.Logger
	Dispatcher     *core.Dispatcher   // job queue; required for /v1/runners/.../jobs + /v1/scans
	Storage        storage.Backend    // optional; events log-only if nil
	Notifier       *notifier.Notifier // optional; per-run webhooks fire after Differ when set

	// TLS configuration. When TLSCertFile + TLSKeyFile are set the server
	// switches to ListenAndServeTLS. Plain HTTP otherwise (default).
	TLSCertFile string
	TLSKeyFile  string
	// TLSClientCAFile, when set, upgrades to mutual TLS — every incoming
	// connection must present a cert signed by this CA. Forms the
	// orchestrator's trust anchor for runner identities.
	TLSClientCAFile string

	// DefaultWatchedPaths gets injected into any SubmitScan job whose
	// WatchedPaths is empty. Loaded from config.yaml at startup; nil
	// disables the fallback (jobs without paths emit no file events).
	DefaultWatchedPaths []proto.WatchedPath
}

// New constructs a Server. It doesn't listen until Serve() is called.
// If opts.Dispatcher is nil, an in-process dispatcher is allocated.
func New(opts Options) *Server {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if opts.OrchestratorID == "" {
		opts.OrchestratorID = "fangs-orchestrator"
	}
	d := opts.Dispatcher
	if d == nil {
		d = core.New()
	}
	s := &Server{
		addr:                opts.Addr,
		orchestratorID:      opts.OrchestratorID,
		version:             opts.Version,
		logger:              logger,
		dispatcher:          d,
		store:               opts.Storage,
		runners:             make(map[string]registeredRunner),
		differTimers:        make(map[string]*time.Timer),
		tlsCertFile:         opts.TLSCertFile,
		tlsKeyFile:          opts.TLSKeyFile,
		tlsClientCAFile:     opts.TLSClientCAFile,
		defaultWatchedPaths: opts.DefaultWatchedPaths,
	}
	if opts.Storage != nil {
		s.differ = differ.New(opts.Storage, logger)
	}
	s.notifier = opts.Notifier
	return s
}

// scheduleDiffer debounces Differ invocations per run_id. Each
// event-batch POST resets the 2s timer; when the timer fires, the
// Differ runs ONCE on the full event set. Calling this from a hot path
// is cheap — Reset is O(1).
func (s *Server) scheduleDiffer(runID string) {
	if s.differ == nil {
		return
	}
	const debounce = 2 * time.Second
	s.differMu.Lock()
	defer s.differMu.Unlock()
	if t, ok := s.differTimers[runID]; ok {
		t.Reset(debounce)
		return
	}
	s.differTimers[runID] = time.AfterFunc(debounce, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		n, err := s.differ.AnalyzeRun(ctx, runID)
		if err != nil {
			s.logger.Warn("differ analyze", "err", err, "run_id", runID)
		} else {
			s.logger.Info("differ complete", "run_id", runID, "deviations", n)
		}
		s.differMu.Lock()
		delete(s.differTimers, runID)
		s.differMu.Unlock()
		// Fire webhooks. Notifier short-circuits when n == 0; for n > 0
		// it spawns per-target retry goroutines and returns immediately.
		if s.notifier != nil && err == nil && n > 0 {
			notifyCtx, notifyCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer notifyCancel()
			if err := s.notifier.Trigger(notifyCtx, runID); err != nil {
				s.logger.Warn("notifier trigger", "err", err, "run_id", runID)
			}
		}
	})
}

// Mount registers the orchestrator's /v1/* routes onto the given mux.
// Callers wiring extra handlers (e.g. the UI) onto the same listen address
// can share a single mux: build it, Mount the API, mount whatever else,
// then pass it to ServeWith.
func (s *Server) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("POST /v1/runners/register", s.handleRegister)
	mux.HandleFunc("POST /v1/runners/{id}/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("GET /v1/runners/{id}/jobs", s.handlePollJob)
	mux.HandleFunc("POST /v1/scans", s.handleQueueScan)
	mux.HandleFunc("POST /v1/runs/{run_id}/events", s.handleEvents)
	mux.HandleFunc("POST /v1/runs/{run_id}/result", s.handleScanResult)
}

// ServeWith listens on s.addr serving the given handler. Blocks until ctx
// is canceled or the listener returns an error. Used by Serve and by main
// when the UI shares the mux. Also starts the stale-runner pruner.
//
// Transport selection:
//   - tlsCertFile + tlsKeyFile empty  → plain HTTP (development default)
//   - both set                        → HTTPS (server TLS)
//   - tlsClientCAFile also set        → mTLS: every connection must
//     present a cert signed by the CA
func (s *Server) ServeWith(ctx context.Context, handler http.Handler) error {
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Build TLS config when configured.
	tlsEnabled := s.tlsCertFile != "" && s.tlsKeyFile != ""
	if tlsEnabled {
		cfg, err := buildServerTLSConfig(s.tlsClientCAFile)
		if err != nil {
			return fmt.Errorf("tls config: %w", err)
		}
		srv.TLSConfig = cfg
	}

	// Stale-runner pruner: every 30s, evict runners that haven't pinged
	// for more than 3× HeartbeatInterval (= 90s by default). Keeps the
	// UI's "registered" list honest after a runner dies without
	// announcing it.
	go s.prunerLoop(ctx, 30*time.Second, 90*time.Second)

	errCh := make(chan error, 1)
	go func() {
		scheme := "http"
		if tlsEnabled {
			scheme = "https"
			if s.tlsClientCAFile != "" {
				scheme = "https (mTLS)"
			}
		}
		s.logger.Info("orchestrator listening", "addr", s.addr, "scheme", scheme)
		var err error
		if tlsEnabled {
			err = srv.ListenAndServeTLS(s.tlsCertFile, s.tlsKeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("http shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// Serve starts the HTTP server with only the /v1/* routes attached.
// Preserved for callers that don't share the mux with the UI.
func (s *Server) Serve(ctx context.Context) error {
	mux := http.NewServeMux()
	s.Mount(mux)
	return s.ServeWith(ctx, mux)
}

// --- handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, proto.HealthResponse{
		Status:         "ok",
		OrchestratorID: s.orchestratorID,
		Version:        s.version,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var reg proto.RunnerRegistration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		writeError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if reg.RunnerID == "" {
		writeError(w, http.StatusBadRequest, "missing runner_id")
		return
	}
	if reg.ProtoVersion != proto.CurrentProtoVersion {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("proto_version %d != orchestrator %d", reg.ProtoVersion, proto.CurrentProtoVersion))
		return
	}

	now := time.Now()
	s.mu.Lock()
	_, existed := s.runners[reg.RunnerID]
	s.runners[reg.RunnerID] = registeredRunner{
		Registration: reg,
		RegisteredAt: now,
		LastSeen:     now,
	}
	s.mu.Unlock()

	s.logger.Info("runner registered",
		"runner_id", reg.RunnerID,
		"hostname", reg.Hostname,
		"kernel", reg.KernelVersion,
		"capabilities", reg.Capabilities,
		"replaced_existing", existed,
	)

	writeJSON(w, http.StatusOK, proto.RegistrationAck{
		OK:                true,
		OrchestratorID:    s.orchestratorID,
		JobPollInterval:   5 * time.Second,
		HeartbeatInterval: 30 * time.Second,
	})
}

// handleHeartbeat updates the runner's LastSeen + optional status fields.
// Returns ok:false + unknown_runner:true when the runner-id isn't in the
// registry — the runner uses this to detect orchestrator restarts and
// re-register without operator intervention.
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	runnerID := r.PathValue("id")
	if runnerID == "" {
		writeError(w, http.StatusBadRequest, "runner id required")
		return
	}
	var hb proto.Heartbeat
	if r.ContentLength > 0 {
		if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&hb); err != nil {
			writeError(w, http.StatusBadRequest, "decode heartbeat: "+err.Error())
			return
		}
	}

	s.mu.Lock()
	rr, ok := s.runners[runnerID]
	if !ok {
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, proto.HeartbeatAck{OK: false, UnknownRunner: true})
		return
	}
	rr.LastSeen = time.Now()
	if hb.ActiveRunID != "" {
		rr.ActiveRunID = hb.ActiveRunID
	} else {
		rr.ActiveRunID = ""
	}
	if hb.Status != "" {
		rr.Status = hb.Status
	}
	rr.EventsQueued = hb.EventsQueued
	s.runners[runnerID] = rr
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, proto.HeartbeatAck{OK: true})
}

// handlePollJob is the long-poll endpoint a runner calls to fetch the
// next job assigned to it. Returns 200 + Job body, or 204 No Content if
// the wait expires with no work available. We cap the server-side wait
// at 25s so loadbalancer / proxy idle timeouts don't break the
// connection.
func (s *Server) handlePollJob(w http.ResponseWriter, r *http.Request) {
	runnerID := r.PathValue("id")
	if runnerID == "" {
		writeError(w, http.StatusBadRequest, "missing runner id")
		return
	}
	s.mu.Lock()
	_, known := s.runners[runnerID]
	s.mu.Unlock()
	if !known {
		writeError(w, http.StatusNotFound, "runner not registered; POST /v1/runners/register first")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	job, ok := s.dispatcher.PollJob(ctx, runnerID)
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.logger.Info("dispatched job",
		"runner_id", runnerID,
		"kind", job.Kind,
		"cgroup_path", job.CgroupPath,
		"watched_paths", len(job.WatchedPaths),
	)
	writeJSON(w, http.StatusOK, job)
}

// SubmitScan is the single entry point for queuing a scan. Used by
// both the HTTP /v1/scans handler and the Watcher. Defaults job kind,
// duration, run_id, dispatch timestamp; writes the runs row; enqueues
// the job for the target runner.
//
// Returns the assigned run_id hex string.
func (s *Server) SubmitScan(ctx context.Context, targetRunner string, job proto.Job) (string, error) {
	s.mu.Lock()
	_, known := s.runners[targetRunner]
	s.mu.Unlock()
	if !known {
		return "", fmt.Errorf("target_runner %q not registered", targetRunner)
	}

	if job.Kind == "" {
		job.Kind = "sensor_only"
	}
	if job.Duration == 0 {
		job.Duration = 10 * time.Second
	}
	// Stamp the orchestrator's configured default watched paths when
	// the incoming job omitted them. Lets the CLI (`fangs scan submit`,
	// `fangs package add`) and the watcher's auto-submit share one
	// source of truth — the orchestrator config — instead of each
	// caller maintaining its own copy.
	if len(job.WatchedPaths) == 0 && len(s.defaultWatchedPaths) > 0 {
		// Defensive copy so the caller can't mutate the shared slice.
		paths := make([]proto.WatchedPath, len(s.defaultWatchedPaths))
		copy(paths, s.defaultWatchedPaths)
		job.WatchedPaths = paths
	}
	if job.RunID == ([16]byte{}) {
		job.RunID = core.SyntheticRunID()
	}
	job.DispatchedAt = time.Now()
	runIDHex := fmt.Sprintf("%x", job.RunID)

	if s.store != nil {
		run := storage.Run{
			ID:          runIDHex,
			PackageName: job.PackageName,
			Version:     job.Version,
			State:       storage.RunStatePending,
			Attempt:     1,
		}
		if run.PackageName == "" && job.Sandbox != nil {
			// Fall back to image name for ad-hoc smoke runs that don't
			// supply an explicit package_name.
			run.PackageName = job.Sandbox.Image
		}
		if err := s.store.CreateRun(ctx, run); err != nil && !errors.Is(err, storage.ErrConflict) {
			s.logger.Warn("persist run", "err", err, "run_id", runIDHex)
		}
	}

	s.dispatcher.QueueJob(targetRunner, job)
	if s.metrics != nil {
		s.metrics.ObserveScanQueued()
	}

	s.logger.Info("queued job",
		"target_runner", targetRunner,
		"kind", job.Kind,
		"package", job.PackageName,
		"version", job.Version,
		"queue_depth", s.dispatcher.QueueDepth(targetRunner),
	)
	return runIDHex, nil
}

// FirstRegisteredRunner returns one runner id from the registered set.
// The Watcher uses this to pick a destination when the operator
// hasn't configured a default. Returns "" if no runners are registered.
func (s *Server) FirstRegisteredRunner() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.runners {
		return id
	}
	return ""
}

// handleQueueScan is the HTTP wrapper around SubmitScan.
func (s *Server) handleQueueScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetRunner string `json:"target_runner"`
		Job          proto.Job
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.TargetRunner == "" {
		writeError(w, http.StatusBadRequest, "missing target_runner")
		return
	}
	runID, err := s.SubmitScan(r.Context(), req.TargetRunner, req.Job)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"queued": true,
		"run_id": runID,
	})
}

// handleEvents accepts a stream of EventBatch JSON objects from a runner.
// Body is newline-delimited JSON (NDJSON), one EventBatch per line. We
// read until EOF or the client closes; each batch's events are persisted
// (if storage is configured) and logged.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	runIDHex := r.PathValue("run_id")
	if runIDHex == "" {
		writeError(w, http.StatusBadRequest, "missing run_id")
		return
	}

	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	var batches, events, persisted int
	for {
		var batch proto.EventBatch
		if err := dec.Decode(&batch); err != nil {
			if err == io.EOF {
				break
			}
			s.logger.Warn("decode EventBatch", "run_id", runIDHex, "err", err, "batches_so_far", batches)
			writeError(w, http.StatusBadRequest, "decode batch: "+err.Error())
			return
		}
		batches++
		events += len(batch.Events)

		// Per-type metric — counts every event arriving regardless of
		// whether storage is configured.
		if s.metrics != nil {
			perType := map[string]int{}
			for _, env := range batch.Events {
				perType[env.Type.String()]++
			}
			for t, n := range perType {
				s.metrics.ObserveEvent(t, n)
			}
		}

		if s.store != nil && len(batch.Events) > 0 {
			rows := make([]storage.EventRow, 0, len(batch.Events))
			for _, env := range batch.Events {
				payload, err := json.Marshal(env.Payload)
				if err != nil {
					s.logger.Warn("marshal event payload", "err", err, "run_id", runIDHex)
					continue
				}
				rows = append(rows, storage.EventRow{
					RunID: runIDHex,
					TsNS:  time.Now().UnixNano(),
					Type:  env.Type.String(),
					Data:  payload,
				})
			}
			if err := s.store.AppendEvents(r.Context(), runIDHex, rows); err != nil {
				s.logger.Warn("persist events", "err", err, "run_id", runIDHex, "batch_size", len(rows))
			} else {
				persisted += len(rows)
			}
		}

		s.logger.Info("received event batch",
			"run_id", runIDHex,
			"seq", batch.Seq,
			"events_in_batch", len(batch.Events),
			"running_total", events,
		)
	}
	if s.store != nil {
		// Best-effort: stream-end == run done. The runner doesn't post a
		// terminal status today; when ScanResult lands (P2P.8) we'll
		// move state transitions there.
		if err := s.store.UpdateRunState(r.Context(), runIDHex, storage.RunStateDone, ""); err != nil && !errors.Is(err, storage.ErrNotFound) {
			s.logger.Warn("mark run done", "err", err, "run_id", runIDHex)
		}
	}
	// Debounce-schedule the Differ. The runner sends events in many
	// small POSTs; we want analysis to run ONCE on the complete set,
	// not per-batch.
	s.scheduleDiffer(runIDHex)
	s.logger.Info("event stream closed",
		"run_id", runIDHex,
		"batches", batches,
		"events", events,
		"persisted", persisted,
	)
	writeJSON(w, http.StatusOK, map[string]any{
		"received_batches": batches,
		"received_events":  events,
		"persisted":        persisted,
	})
}

// handleScanResult finalizes a run: the runner posts a ScanResult after
// the sandbox + sensor have wrapped, and the orchestrator transitions
// the run to done/failed with metrics stored on the row.
func (s *Server) handleScanResult(w http.ResponseWriter, r *http.Request) {
	runIDHex := r.PathValue("run_id")
	if runIDHex == "" {
		writeError(w, http.StatusBadRequest, "run_id required")
		return
	}
	var result proto.ScanResult
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&result); err != nil {
		writeError(w, http.StatusBadRequest, "decode ScanResult: "+err.Error())
		return
	}
	if result.Status != "ok" && result.Status != "failed" && result.Status != "timeout" {
		writeError(w, http.StatusBadRequest, "status must be ok|failed|timeout")
		return
	}
	if s.store == nil {
		// No storage — still ack so the runner doesn't retry forever, but
		// log the result.
		s.logger.Info("scan result (no store)",
			"run_id", runIDHex, "status", result.Status, "events", result.EventsEmitted,
			"dropped", result.EventsDropped, "duration", result.Duration)
		writeJSON(w, http.StatusOK, map[string]any{"recorded": false})
		return
	}
	err := s.store.RecordScanResult(r.Context(), runIDHex, storage.ScanResult{
		Status:        result.Status,
		Reason:        result.Reason,
		EventsEmitted: result.EventsEmitted,
		EventsDropped: int64(result.EventsDropped),
		DurationNS:    int64(result.Duration),
	})
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "run not found")
			return
		}
		s.logger.Warn("RecordScanResult", "err", err, "run_id", runIDHex)
		writeError(w, http.StatusInternalServerError, "record scan result: "+err.Error())
		return
	}
	if s.metrics != nil && result.EventsDropped > 0 {
		s.metrics.ObserveEventsDropped(int64(result.EventsDropped))
	}
	s.logger.Info("scan result recorded",
		"run_id", runIDHex, "status", result.Status, "events", result.EventsEmitted,
		"dropped", result.EventsDropped, "duration", result.Duration)
	writeJSON(w, http.StatusOK, map[string]any{"recorded": true})
}

// --- helpers ---

// buildServerTLSConfig produces the tls.Config used when the orchestrator
// is listening with TLS. Returns a server-only config when clientCAFile
// is empty; otherwise upgrades to mTLS by loading the CA pool and
// requiring + verifying every client cert.
func buildServerTLSConfig(clientCAFile string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if clientCAFile == "" {
		return cfg, nil
	}
	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA %q: %w", clientCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("client CA %q contained no usable certs", clientCAFile)
	}
	cfg.ClientCAs = pool
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	return cfg, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// prunerLoop walks the runners map every `tick` and evicts entries whose
// LastSeen is older than `cutoff`. Runs until ctx is canceled.
func (s *Server) prunerLoop(ctx context.Context, tick, cutoff time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		var evicted []string
		s.mu.Lock()
		for id, rr := range s.runners {
			if now.Sub(rr.LastSeen) > cutoff {
				delete(s.runners, id)
				evicted = append(evicted, id)
			}
		}
		s.mu.Unlock()
		for _, id := range evicted {
			s.logger.Warn("runner pruned — no heartbeat",
				"runner_id", id, "cutoff", cutoff)
		}
	}
}

// RegisteredRunners returns a snapshot of currently-registered runner IDs.
func (s *Server) RegisteredRunners() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.runners))
	for id := range s.runners {
		out = append(out, id)
	}
	return out
}

// RunnerSnapshot is a view-friendly copy of one runner's registration
// record. Returned by RegisteredRunnersDetail for the UI / status
// endpoints — the internal registeredRunner stays unexported.
type RunnerSnapshot struct {
	ID            string
	Hostname      string
	KernelVersion string
	ProtoVersion  uint32
	Capabilities  []string
	RegisteredAt  time.Time
	LastSeen      time.Time
	ActiveRunID   string
	Status        string
	EventsQueued  int
}

// RegisteredRunnersDetail returns a snapshot of all currently-registered
// runners with full registration metadata. The slice ordering is unstable
// (map iteration); callers that need a stable view should sort.
func (s *Server) RegisteredRunnersDetail() []RunnerSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RunnerSnapshot, 0, len(s.runners))
	for _, r := range s.runners {
		out = append(out, RunnerSnapshot{
			ID:            r.Registration.RunnerID,
			Hostname:      r.Registration.Hostname,
			KernelVersion: r.Registration.KernelVersion,
			ProtoVersion:  r.Registration.ProtoVersion,
			Capabilities:  append([]string{}, r.Registration.Capabilities...),
			RegisteredAt:  r.RegisteredAt,
			LastSeen:      r.LastSeen,
			ActiveRunID:   r.ActiveRunID,
			Status:        r.Status,
			EventsQueued:  r.EventsQueued,
		})
	}
	return out
}
