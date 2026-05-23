// SPDX-License-Identifier: Apache-2.0
//
// Package notifier turns Differ-emitted deviations into outbound webhook
// POSTs. Per-run summary semantics: when a run finishes with N>0
// deviations, ONE webhook fires per configured + enabled target with a
// payload that lists every finding.
//
// Targets live in the `notifiers` table (managed by `fangs notifier`
// CLI + the optional -notifiers-file boot-time loader). Each delivery
// attempt is logged in `notifications` for audit + post-mortem.
//
// Retry policy: in-memory exponential backoff (1s base, ×2 per attempt,
// ±25% jitter), up to 5 attempts. 2xx = sent. 4xx (except 408/429) =
// permanent failure, no retry. 5xx + network errors = transient, retry.
// State doesn't persist across orchestrator restarts — when an
// orchestrator is killed mid-retry, the half-delivered run is lost.
// That's acceptable for v1; the audit log records the last attempt.
//
// HMAC: per-target opt-in via SecretEnv (a process env-var name). When
// set, we add `X-FANGS-Signature: sha256=<hex>` where hex is
// HMAC-SHA256(env-var-value, body). Slack and Discord templates ignore
// SecretEnv even when set (the URL is the secret in those models).
package notifier

import (
	"bytes"
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

// Notifier dispatches per-run deviation summaries to every configured
// webhook target.
type Notifier struct {
	store      storage.Backend
	httpClient *http.Client
	logger     *slog.Logger
	maxAttempt int
	baseDelay  time.Duration

	metrics metricsSink
}

// metricsSink is the contract the notifier needs from the metrics
// package — defined locally so notifier doesn't depend on prometheus.
type metricsSink interface {
	ObserveNotification(notifier, status string)
}

// SetMetrics wires the metrics sink. nil is fine — instrumentation
// no-ops.
func (n *Notifier) SetMetrics(m metricsSink) { n.metrics = m }

// Options configures Notifier.
type Options struct {
	Store       storage.Backend
	Logger      *slog.Logger
	HTTPTimeout time.Duration
	MaxAttempts int
	BaseDelay   time.Duration
}

// New constructs a Notifier.
func New(opts Options) *Notifier {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	timeout := opts.HTTPTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	max := opts.MaxAttempts
	if max == 0 {
		max = 5
	}
	base := opts.BaseDelay
	if base == 0 {
		base = 1 * time.Second
	}
	return &Notifier{
		store:      opts.Store,
		httpClient: &http.Client{Timeout: timeout},
		logger:     logger,
		maxAttempt: max,
		baseDelay:  base,
	}
}

// Trigger fans out per-run summary webhooks for the given run. Loads
// the run + its deviations + the enabled notifiers, then spawns one
// goroutine per (notifier × run) to handle the retry loop independently.
// Non-blocking: callers can fire-and-forget.
//
// Returns immediately with an error only when the pre-flight DB queries
// fail. Per-target delivery results land in the `notifications` table
// via RecordNotification.
func (n *Notifier) Trigger(ctx context.Context, runID string) error {
	run, err := n.store.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("notifier: load run: %w", err)
	}
	devs, err := n.store.ListDeviations(ctx, runID)
	if err != nil {
		return fmt.Errorf("notifier: load deviations: %w", err)
	}
	if len(devs) == 0 {
		// Nothing to alert on. Don't even spend a query on the targets.
		return nil
	}
	targets, err := n.store.ListNotifiers(ctx)
	if err != nil {
		return fmt.Errorf("notifier: load notifiers: %w", err)
	}
	maxSev := highestSeverity(devs)
	for _, t := range targets {
		if !t.Enabled {
			continue
		}
		if t.MinSeverity != "" && severityRank(maxSev) < severityRank(t.MinSeverity) {
			n.logger.Info("notifier skip — below min_severity",
				"notifier", t.Name, "max_sev", maxSev, "min_sev", t.MinSeverity, "run_id", runID)
			continue
		}
		// Detach from request context so a slow retry loop isn't
		// canceled when the calling differ goroutine returns.
		target := t
		runCopy := run
		devsCopy := devs
		go n.deliverWithRetry(context.Background(), target, runCopy, devsCopy)
	}
	return nil
}

// deliverWithRetry runs the per-target retry loop, logging each attempt
// to the notifications table.
func (n *Notifier) deliverWithRetry(ctx context.Context, target storage.NotifierRow, run storage.Run, devs []storage.DeviationRow) {
	rend, ok := renderers[target.Template]
	if !ok {
		n.logger.Warn("notifier unknown template", "notifier", target.Name, "template", target.Template)
		n.recordAttempt(ctx, target, run, 1, "permanent", 0, "", fmt.Errorf("unknown template %q", target.Template), len(devs), nil)
		return
	}
	body, contentType, err := rend(run, devs)
	if err != nil {
		n.logger.Warn("notifier render failed", "notifier", target.Name, "err", err)
		n.recordAttempt(ctx, target, run, 1, "permanent", 0, "", err, len(devs), nil)
		return
	}

	for attempt := 1; attempt <= n.maxAttempt; attempt++ {
		code, respBody, postErr := n.post(ctx, target, body, contentType)
		status := classify(code, postErr)

		var nextAt *time.Time
		if status == "failed" && attempt < n.maxAttempt {
			t := time.Now().Add(n.backoff(attempt))
			nextAt = &t
		}
		n.recordAttempt(ctx, target, run, attempt, status, code, respBody, postErr, len(devs), nextAt)
		if n.metrics != nil {
			n.metrics.ObserveNotification(target.Name, status)
		}

		if status == "sent" {
			n.logger.Info("notifier delivered",
				"notifier", target.Name, "run_id", run.ID, "attempt", attempt,
				"http_status", code, "deviations", len(devs))
			return
		}
		if status == "permanent" {
			n.logger.Warn("notifier permanent failure — no retry",
				"notifier", target.Name, "run_id", run.ID, "http_status", code, "err", postErr)
			return
		}
		// Transient — sleep and retry.
		if attempt < n.maxAttempt {
			d := n.backoff(attempt)
			n.logger.Warn("notifier transient failure — retrying",
				"notifier", target.Name, "run_id", run.ID, "attempt", attempt,
				"http_status", code, "err", postErr, "next_in", d)
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return
			}
		}
	}
	n.logger.Warn("notifier giving up after max attempts",
		"notifier", target.Name, "run_id", run.ID, "max_attempts", n.maxAttempt)
}

// post sends the body to the target and returns (status code, response
// body excerpt, error). Network errors return (0, "", err).
func (n *Notifier) post(ctx context.Context, target storage.NotifierRow, body []byte, contentType string) (int, string, error) {
	parsed, err := url.Parse(target.URL)
	if err != nil {
		return 0, "", fmt.Errorf("invalid url: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return 0, "", fmt.Errorf("unsupported scheme %q (https/http only)", parsed.Scheme)
	}
	// http:// is rejected by default — operators wanting it would have to
	// build a custom orchestrator. Keeps localhost-loopback testing
	// possible via http://127.0.0.1.
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Host) {
		return 0, "", fmt.Errorf("plain http only allowed for loopback hosts (got %s)", parsed.Host)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "fangs-orchestrator")

	// Apply target headers if configured.
	for k, v := range parseHeaders(target.Headers) {
		req.Header.Set(k, v)
	}

	// HMAC signing — skip for slack/discord (URL secret model).
	if target.SecretEnv != "" && target.Template != "slack" && target.Template != "discord" {
		secret := os.Getenv(target.SecretEnv)
		if secret == "" {
			return 0, "", fmt.Errorf("secret env %q is empty", target.SecretEnv)
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set("X-FANGS-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return resp.StatusCode, string(excerpt), nil
}

func (n *Notifier) recordAttempt(ctx context.Context, target storage.NotifierRow, run storage.Run,
	attempt int, status string, code int, respBody string, postErr error, devCount int, nextAt *time.Time) {

	errMsg := ""
	if postErr != nil {
		errMsg = postErr.Error()
	}
	now := time.Now().UTC()
	row := storage.NotificationRow{
		ID:              newNotificationID(target.Name, run.ID, attempt),
		RunID:           run.ID,
		NotifierName:    target.Name,
		Attempt:         attempt,
		Status:          status,
		LastAttemptedAt: &now,
		NextAttemptAt:   nextAt,
		ResponseCode:    code,
		ResponseBody:    respBody,
		ErrorMsg:        errMsg,
		DeviationCount:  devCount,
		CreatedAt:       now,
	}
	if err := n.store.RecordNotification(ctx, row); err != nil {
		n.logger.Warn("notifier: RecordNotification", "err", err)
	}
}

// backoff returns the delay before the (attempt+1)-th try. Exponential
// with ±25% jitter so concurrent notifiers don't thunder.
func (n *Notifier) backoff(attempt int) time.Duration {
	d := n.baseDelay * (1 << (attempt - 1))
	jitter := time.Duration(mrand.Int64N(int64(d) / 2)) // up to 50% of d
	return d - d/4 + jitter                             // d × [0.75, 1.25)
}

// classify maps (http code, err) to one of: sent | permanent | failed.
func classify(code int, err error) string {
	if err != nil {
		return "failed" // network/timeout — retry
	}
	switch {
	case code >= 200 && code < 300:
		return "sent"
	case code == 408 || code == 429:
		return "failed" // retry — server asked us to or timed out
	case code >= 400 && code < 500:
		return "permanent" // 4xx that isn't 408/429 — won't help to retry
	case code >= 500:
		return "failed"
	default:
		return "failed"
	}
}

// severityRank — higher = more severe. Returns 0 for empty/unknown so
// any non-empty target.MinSeverity rejects unseverity'd events.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func highestSeverity(devs []storage.DeviationRow) string {
	best := ""
	bestRank := 0
	for _, d := range devs {
		if r := severityRank(d.Severity); r > bestRank {
			best = d.Severity
			bestRank = r
		}
	}
	return best
}

// isLoopbackHost — only http allowed for these hosts (dev/testing).
func isLoopbackHost(host string) bool {
	// Strip :port if present.
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// newNotificationID returns a stable-ish unique id per (target, run, attempt).
// 16 hex chars of random — collision-free in practice.
func newNotificationID(notifierName, runID string, attempt int) string {
	var b [8]byte
	_, _ = crand.Read(b[:])
	return fmt.Sprintf("%s-%d", hex.EncodeToString(b[:]), attempt)
}

// parseHeaders parses a JSON object string into a map. Returns nil on
// any parse failure (best-effort — operators get a warning at upsert
// time instead).
func parseHeaders(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	return parseJSONStringMap(raw)
}
