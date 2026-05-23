// SPDX-License-Identifier: Apache-2.0
//
// fangs-runner is the FANGS execution-plane binary. It registers with an
// orchestrator, long-polls for jobs, runs the sensor for the job's
// requested duration, and streams captured events back over HTTP.
//
// One job at a time for now — the inner sensor.Sensor isn't safe to
// re-attach concurrently because a single CGMAP entry is per cgroup
// id. Multi-cgroup-per-runner concurrency lands later.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/irchaosclub/FANGS/internal/runner/agent"
	"github.com/irchaosclub/FANGS/internal/runner/sandbox"
	"github.com/irchaosclub/FANGS/internal/runner/sensor"
	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

func main() {
	var (
		orchestratorURL = flag.String("orchestrator", "http://127.0.0.1:8443", "orchestrator base URL")
		runnerID        = flag.String("runner-id", "", "stable identifier for this runner (default: hostname)")
		tlsCA           = flag.String("tls-ca", "", "PEM-encoded CA bundle the orchestrator's server cert is signed by (required for https://)")
		tlsCert         = flag.String("tls-cert", "", "PEM-encoded client cert to present to the orchestrator (for mTLS)")
		tlsKey          = flag.String("tls-key", "", "PEM-encoded private key paired with -tls-cert")
		timeout         = flag.Duration("timeout", 30*time.Second, "per-request timeout for orchestrator control-plane calls")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cli, err := agent.New(agent.Options{
		OrchestratorURL: *orchestratorURL,
		RunnerID:        *runnerID,
		TLSCAFile:       *tlsCA,
		TLSCertFile:     *tlsCert,
		TLSKeyFile:      *tlsKey,
		Timeout:         *timeout,
		Logger:          logger,
	})
	if err != nil {
		logger.Error("agent.New", "err", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Attach the sensor ONCE at startup so probes are live before any
	// container starts. Per-job we just call AddCgroup / RemoveCgroup —
	// closes the container-start vs sensor-attach race window (Q21).
	sens, err := sensor.New(sensor.Options{
		Logger:        logger,
		EnsureTracefs: true,
		DedupWindow:   5 * time.Second,
	})
	if err != nil {
		logger.Error("sensor.New", "err", err)
		os.Exit(1)
	}
	defer sens.Close()

	// Single long-lived event stream. Goroutine forwards events to the
	// per-job streamer that's installed by runJob.
	var (
		streamerMu sync.Mutex
		curStream  *agent.EventStreamer
		curRunHex  string
	)
	go func() {
		for ev := range sens.Events(ctx) {
			streamerMu.Lock()
			st := curStream
			runID := curRunHex
			streamerMu.Unlock()
			if st == nil {
				continue
			}
			_ = runID // currently informational; streamer carries the run id
			st.Send(proto.EventEnvelope{Type: ev.EventType(), Payload: ev})
		}
	}()
	setStreamer := func(s *agent.EventStreamer, runHex string) {
		streamerMu.Lock()
		curStream = s
		curRunHex = runHex
		streamerMu.Unlock()
	}

	if err := cli.Register(ctx); err != nil {
		logger.Error("register with orchestrator", "err", err, "orchestrator", *orchestratorURL)
		os.Exit(1)
	}

	// Heartbeat goroutine — pings the orchestrator on cli.HeartbeatInterval
	// so its `runners` map keeps LastSeen fresh and the UI can show
	// liveness. Includes the active run id when a job is in flight (read
	// under streamerMu). If the orchestrator forgets us (restarted, evicted),
	// re-register transparently.
	go func() {
		interval := cli.HeartbeatInterval()
		if interval <= 0 {
			interval = 30 * time.Second
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			streamerMu.Lock()
			runHex := curRunHex
			streamerMu.Unlock()
			status := "idle"
			if runHex != "" {
				status = "running"
			}
			hbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			alive, err := cli.SendHeartbeat(hbCtx, proto.Heartbeat{
				ActiveRunID: runHex,
				Status:      status,
			})
			cancel()
			if err != nil {
				logger.Warn("heartbeat failed", "err", err)
				continue
			}
			if !alive {
				logger.Warn("orchestrator forgot us — re-registering")
				if err := cli.Register(ctx); err != nil {
					logger.Warn("re-register failed", "err", err)
				}
			}
		}
	}()

	logger.Info("entering poll loop")
	for {
		if ctx.Err() != nil {
			logger.Info("runner exiting", "reason", ctx.Err())
			return
		}
		job, ok, err := cli.PollJob(ctx)
		if err != nil {
			logger.Warn("poll failed; retrying", "err", err)
			sleepWithCtx(ctx, 2*time.Second)
			continue
		}
		if !ok {
			sleepWithCtx(ctx, cli.JobPollInterval())
			continue
		}
		runJob(ctx, logger, cli, *orchestratorURL, job, sens, setStreamer)
	}
}

// runJob drives one job end-to-end. The sensor is already attached at
// runner startup; runJob just registers the cgroup, runs the sandbox,
// and deregisters. setStreamer routes the persistent sensor's event
// channel to this job's per-run streamer.
func runJob(
	ctx context.Context,
	logger *slog.Logger,
	cli *agent.Client,
	orchestratorURL string,
	job proto.Job,
	sens *sensor.Sensor,
	setStreamer func(*agent.EventStreamer, string),
) {
	runIDHex := fmt.Sprintf("%x", job.RunID)
	logger = logger.With("run_id", runIDHex)
	logger.Info("starting job",
		"kind", job.Kind,
		"cgroup_path", job.CgroupPath,
		"watched_paths", len(job.WatchedPaths),
		"duration", job.Duration.String(),
		"sandbox", job.Sandbox != nil,
	)

	// Final-status tracking. Error paths flip these before returning;
	// the LIFO defer below sees the latest value and POSTs ScanResult.
	// statusMu guards status+reason because the container-watcher
	// goroutine may also write them on container exit.
	jobStart := time.Now()
	var (
		statusMu sync.Mutex
		status   = "ok"
		reason   = ""
	)
	setStatus := func(s, r string) {
		statusMu.Lock()
		status, reason = s, r
		statusMu.Unlock()
	}
	getStatus := func() (string, string) {
		statusMu.Lock()
		defer statusMu.Unlock()
		return status, reason
	}

	// Defer ScanResult POST FIRST so it runs LAST in LIFO order — after
	// streamer.Close + sandbox stop + cgroup tear-down. By that point
	// the streamer has flushed and Stats() reflects final counts.
	var streamerRef *agent.EventStreamer
	defer func() {
		drops, _ := sens.Drops()
		var emitted int64
		if streamerRef != nil {
			emitted = int64(streamerRef.Stats().EventsSent)
		}
		s, r := getStatus()
		sendCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		if err := cli.SendScanResult(sendCtx, runIDHex, proto.ScanResult{
			RunID:         job.RunID,
			Status:        s,
			Reason:        r,
			EventsEmitted: emitted,
			EventsDropped: drops,
			Duration:      time.Since(jobStart),
		}); err != nil {
			logger.Warn("send scan result", "err", err)
		} else {
			logger.Info("scan result posted", "status", s, "events", emitted, "dropped", drops)
		}
	}()

	watched := make([]sensor.WatchedPath, 0, len(job.WatchedPaths))
	for _, wp := range job.WatchedPaths {
		watched = append(watched, sensor.WatchedPath{Prefix: wp.Prefix, CredTagged: wp.CredTagged})
	}

	jobCtx, cancel := context.WithTimeout(ctx, job.Duration)
	defer cancel()

	// Install the streamer first so any events that fire as soon as the
	// container starts get forwarded.
	streamer := agent.NewEventStreamer(jobCtx, orchestratorURL, job.RunID, logger, cli.Transport())
	streamerRef = streamer
	setStreamer(streamer, runIDHex)
	defer func() {
		setStreamer(nil, "")
		streamer.Close()
		stats := streamer.Stats()
		logger.Info("event streamer closed",
			"batches_sent", stats.BatchesSent,
			"events_sent", stats.EventsSent,
			"batch_send_errors", stats.BatchSendErrors,
		)
	}()

	var (
		cgroupID  uint64
		handle    sandbox.Handle
		parentAbs string
	)
	if job.Sandbox != nil {
		// Pre-create a FANGS-managed parent cgroup and register ITS
		// inode in CGMAP before the container starts. The container's
		// processes nest under this parent — sensor catches them from
		// syscall #1 via the ancestor walk. Closes Q21 timing race.
		parentRel, abs, parentCgid, err := sandbox.CreateParentCgroup(runIDHex)
		if err != nil {
			logger.Error("create cgroup parent", "err", err)
			status = "failed"
			reason = "create cgroup parent: " + err.Error()
			return
		}
		parentAbs = abs
		cgroupID = parentCgid
		logger.Info("fangs cgroup parent created", "path", abs, "rel", parentRel, "cgroup_id", parentCgid)

		// Register BEFORE container starts.
		if err := sens.AddCgroup(sensor.AddCgroupOptions{
			CgroupID:     cgroupID,
			RunID:        job.RunID,
			WatchedPaths: watched,
		}); err != nil {
			_ = sandbox.RemoveParentCgroup(parentAbs)
			logger.Error("AddCgroup", "err", err)
			status = "failed"
			reason = "AddCgroup: " + err.Error()
			return
		}
		defer func() {
			if err := sens.RemoveCgroup(cgroupID); err != nil {
				logger.Warn("RemoveCgroup", "err", err, "cgroup_id", cgroupID)
			}
			// Retry rmdir a few times — Docker tears down child cgroup
			// asynchronously, so rmdir on the parent fails with EBUSY
			// until that finishes.
			for i := 0; i < 20; i++ {
				if err := sandbox.RemoveParentCgroup(parentAbs); err == nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			logger.Warn("could not rmdir parent cgroup; leaked", "path", parentAbs)
		}()

		// Now launch the container with CgroupParent set.
		spec := *job.Sandbox
		spec.CgroupParent = parentRel
		driver := sandbox.NewDockerDriver(sandbox.DockerOptions{Logger: logger})
		h, err := driver.Launch(ctx, spec)
		if err != nil {
			logger.Error("sandbox launch failed", "err", err)
			status = "failed"
			reason = "sandbox launch: " + err.Error()
			return
		}
		handle = h
		defer func() {
			grace := job.Sandbox.GracePeriod
			if grace > 0 {
				logger.Info("sandbox main exited; observing grace window", "grace", grace.String())
				select {
				case <-time.After(grace):
				case <-ctx.Done():
				}
			}
			stopCtx, c := context.WithTimeout(context.Background(), 15*time.Second)
			defer c()
			if err := handle.Stop(stopCtx); err != nil {
				logger.Warn("sandbox stop", "err", err, "container_id", handle.ContainerID()[:12])
			} else {
				logger.Info("sandbox stopped", "container_id", handle.ContainerID()[:12])
			}
		}()
	} else {
		id, err := cgroupIDFromPath(job.CgroupPath)
		if err != nil {
			logger.Error("resolve cgroup id", "err", err)
			status = "failed"
			reason = "resolve cgroup id: " + err.Error()
			return
		}
		cgroupID = id
		if err := sens.AddCgroup(sensor.AddCgroupOptions{
			CgroupID:     cgroupID,
			RunID:        job.RunID,
			WatchedPaths: watched,
		}); err != nil {
			logger.Error("AddCgroup", "err", err)
			status = "failed"
			reason = "AddCgroup: " + err.Error()
			return
		}
		defer func() {
			if err := sens.RemoveCgroup(cgroupID); err != nil {
				logger.Warn("RemoveCgroup", "err", err, "cgroup_id", cgroupID)
			}
		}()
	}

	if handle != nil {
		go func() {
			select {
			case res := <-handle.Wait():
				logger.Info("sandbox container exited",
					"exit_code", res.ExitCode,
					"err", res.Err,
				)
				if res.ExitCode != 0 || res.Err != nil {
					setStatus("failed", fmt.Sprintf("container exit_code=%d err=%v", res.ExitCode, res.Err))
				}
				cancel()
			case <-jobCtx.Done():
			}
		}()
	}

	logger.Info("sensor watching cgroup; running for job duration", "registered_cgroup_id", cgroupID)

	<-jobCtx.Done()
	// A deadline-exceeded jobCtx with no prior status flip means the run
	// hit its full Duration without the container exiting on its own —
	// classify as timeout for the orchestrator.
	if s, _ := getStatus(); s == "ok" && errors.Is(jobCtx.Err(), context.DeadlineExceeded) {
		setStatus("timeout", "job duration exceeded before container exit")
	}
	drops, _ := sens.Drops()
	misses := sens.DumpMisses(10)
	missLog := make([]any, 0, len(misses)*2)
	for _, m := range misses {
		missLog = append(missLog, fmt.Sprintf("cgid_%d", m.CgroupID), m.Count)
	}
	logger.Info("job complete", append([]any{"events_dropped", drops, "registered_cgroup_id", cgroupID}, missLog...)...)
}

func cgroupIDFromPath(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat %q: %w", path, err)
	}
	return st.Ino, nil
}

func sleepWithCtx(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
