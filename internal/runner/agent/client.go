// SPDX-License-Identifier: Apache-2.0
//
// Package agent is the runner-side HTTP client that talks to the orchestrator.
// It owns the registration handshake, job polling, event streaming, and
// heartbeat — but doesn't itself run the sensor. The runner binary glues
// the agent (control plane) and the sensor package (data plane) together.
//
// This file lands the registration path. Job polling and event streaming
// arrive in follow-up commits.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

// Client talks to a single orchestrator endpoint. Construct via New(),
// call Register() once at startup, then PollJob/StreamEvents/Heartbeat
// as the runtime workflow demands.
type Client struct {
	baseURL   string
	http      *http.Client
	transport *http.Transport // shared with PollJob/EventStreamer so TLS config carries over
	logger    *slog.Logger

	// State learned from Register().
	orchestratorID    string
	jobPollInterval   time.Duration
	heartbeatInterval time.Duration
	runnerID          string
}

// Options configures a Client.
type Options struct {
	OrchestratorURL string        // e.g. "http://127.0.0.1:8443" or "https://..."
	RunnerID        string        // operator-supplied; defaults to hostname
	Timeout         time.Duration // per-request timeout; default 30s
	Logger          *slog.Logger

	// TLS — used when OrchestratorURL is https://. CAFile is the trust
	// anchor for the orchestrator's server cert (omit to fall back to the
	// system trust store). CertFile + KeyFile are the runner's client
	// cert pair for mTLS; omit for server-TLS-only mode.
	TLSCAFile   string
	TLSCertFile string
	TLSKeyFile  string
}

// New constructs an unregistered Client. Caller must invoke Register
// before any other RPC.
func New(opts Options) (*Client, error) {
	if opts.OrchestratorURL == "" {
		return nil, fmt.Errorf("OrchestratorURL is required")
	}
	if opts.RunnerID == "" {
		host, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("default RunnerID from hostname: %w", err)
		}
		opts.RunnerID = host
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	transport, err := buildClientTransport(opts.TLSCAFile, opts.TLSCertFile, opts.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls transport: %w", err)
	}

	// Build the http.Client carefully: assigning a typed-nil *Transport
	// to the RoundTripper interface field would crash inside net/http
	// (interface non-nil, value nil → segfault on method call). Leave
	// Transport unset for plain-HTTP mode so http.DefaultTransport kicks
	// in via the stdlib's nil-check.
	hc := &http.Client{Timeout: opts.Timeout}
	if transport != nil {
		hc.Transport = transport
	}

	return &Client{
		baseURL:   opts.OrchestratorURL,
		http:      hc,
		transport: transport, // nil when TLS isn't configured; helper getter returns nil too
		logger:    logger,
		runnerID:  opts.RunnerID,
	}, nil
}

// Transport returns the configured *http.Transport (or nil for plain
// HTTP via http.DefaultTransport). Callers that need a separate client
// — long-poll, event streamer — reuse this so TLS config is consistent.
func (c *Client) Transport() *http.Transport { return c.transport }

// buildClientTransport returns an *http.Transport with TLS configured
// per the supplied paths. When all three are empty, returns nil — the
// stdlib uses http.DefaultTransport, which is what we want for plain
// HTTP. When caFile is set, the orchestrator's cert is verified against
// it; when certFile + keyFile are set, the runner presents that cert
// to satisfy mTLS.
func buildClientTransport(caFile, certFile, keyFile string) (*http.Transport, error) {
	if caFile == "" && certFile == "" && keyFile == "" {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("CA %q has no usable certs", caFile)
		}
		cfg.RootCAs = pool
	}
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("both -tls-cert and -tls-key required for mTLS")
		}
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return &http.Transport{TLSClientConfig: cfg}, nil
}

// Register sends RunnerRegistration to the orchestrator. On success it
// stores the orchestrator's reply (poll intervals, orchestrator id) so
// subsequent calls use the right cadence.
func (c *Client) Register(ctx context.Context) error {
	reg := proto.RunnerRegistration{
		RunnerID:      c.runnerID,
		Hostname:      hostname(),
		Capabilities:  []string{"sensor"},
		KernelVersion: kernelVersion(),
		ProtoVersion:  proto.CurrentProtoVersion,
	}
	body, err := json.Marshal(reg)
	if err != nil {
		return fmt.Errorf("marshal registration: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/runners/register", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST /v1/runners/register: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("register: orchestrator returned %d: %s", resp.StatusCode, string(b))
	}

	var ack proto.RegistrationAck
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		return fmt.Errorf("decode RegistrationAck: %w", err)
	}
	if !ack.OK {
		return fmt.Errorf("register: orchestrator returned ok=false")
	}

	c.orchestratorID = ack.OrchestratorID
	c.jobPollInterval = ack.JobPollInterval
	c.heartbeatInterval = ack.HeartbeatInterval
	c.logger.Info("registered with orchestrator",
		"orchestrator_id", c.orchestratorID,
		"job_poll_interval", c.jobPollInterval.String(),
		"heartbeat_interval", c.heartbeatInterval.String(),
	)
	return nil
}

// PollJob long-polls the orchestrator for the next job assigned to this
// runner. Returns (job, true, nil) when one arrives; (zero, false, nil)
// when the server's wait expires with no work (HTTP 204); (zero, false,
// err) on protocol / transport failure.
//
// The runner loops on this with PollInterval-bounded waits between calls
// to avoid hammering the orchestrator on persistent 204 responses.
func (c *Client) PollJob(ctx context.Context) (proto.Job, bool, error) {
	// Build a request with a per-poll timeout slightly longer than the
	// orchestrator's server-side cap (25s) so we let the server win the
	// race and either return a job or 204.
	pollCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s/v1/runners/%s/jobs", c.baseURL, c.runnerID)
	req, err := http.NewRequestWithContext(pollCtx, http.MethodGet, url, nil)
	if err != nil {
		return proto.Job{}, false, fmt.Errorf("build poll request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	// One-shot client for this call: the default Client's Timeout would
	// preempt our context-bounded wait. Reuse the configured transport
	// so TLS/mTLS settings carry over. Mind the typed-nil interface
	// trap — only set Transport when we actually have one.
	oneShot := &http.Client{}
	if c.transport != nil {
		oneShot.Transport = c.transport
	}
	resp, err := oneShot.Do(req)
	if err != nil {
		return proto.Job{}, false, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return proto.Job{}, false, nil
	case http.StatusOK:
		var job proto.Job
		if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
			return proto.Job{}, false, fmt.Errorf("decode Job: %w", err)
		}
		return job, true, nil
	case http.StatusNotFound:
		return proto.Job{}, false, fmt.Errorf("runner not registered; re-register before polling")
	default:
		body, _ := io.ReadAll(resp.Body)
		return proto.Job{}, false, fmt.Errorf("orchestrator returned %d: %s", resp.StatusCode, string(body))
	}
}

// OrchestratorID returns the id learned during Register, or "" if not yet
// registered.
func (c *Client) OrchestratorID() string { return c.orchestratorID }

// JobPollInterval returns the cadence the orchestrator asked us to poll at.
func (c *Client) JobPollInterval() time.Duration { return c.jobPollInterval }

// HeartbeatInterval returns the cadence the orchestrator asked us to ping.
func (c *Client) HeartbeatInterval() time.Duration { return c.heartbeatInterval }

// SendScanResult posts the final ScanResult for a run. The orchestrator
// transitions the run's state to done/failed and stores the metrics
// (events emitted/dropped, duration) on the run row.
func (c *Client) SendScanResult(ctx context.Context, runIDHex string, result proto.ScanResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal ScanResult: %w", err)
	}
	url := fmt.Sprintf("%s/v1/runs/%s/result", c.baseURL, runIDHex)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("orchestrator returned %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// SendHeartbeat pings the orchestrator, refreshing the runner's
// LastSeen + active status. Returns (true, nil) on a fresh ack;
// (false, nil) when the orchestrator no longer knows about this runner
// (re-register needed); (false, err) on transport failure.
func (c *Client) SendHeartbeat(ctx context.Context, hb proto.Heartbeat) (alive bool, err error) {
	hb.RunnerID = c.runnerID
	body, err := json.Marshal(hb)
	if err != nil {
		return false, fmt.Errorf("marshal heartbeat: %w", err)
	}
	url := fmt.Sprintf("%s/v1/runners/%s/heartbeat", c.baseURL, c.runnerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return false, fmt.Errorf("orchestrator returned %d: %s", resp.StatusCode, string(b))
	}
	var ack proto.HeartbeatAck
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		return false, fmt.Errorf("decode HeartbeatAck: %w", err)
	}
	if ack.UnknownRunner {
		return false, nil
	}
	return ack.OK, nil
}

// --- helpers ---

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func kernelVersion() string {
	// We only run on Linux, but make it a soft read so a misconfigured
	// build doesn't crash. Reads /proc/sys/kernel/osrelease (works
	// without needing a uname syscall wrapper).
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return runtime.GOOS + "-unknown"
	}
	return string(bytes.TrimSpace(b))
}
