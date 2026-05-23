// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/watcher"
	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

func (a *app) scanCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("scan: expected subcommand (submit)")
	}
	switch args[0] {
	case "submit":
		return a.scanSubmit(ctx, args[1:])
	default:
		return fmt.Errorf("scan: unknown subcommand %q", args[0])
	}
}

func (a *app) scanSubmit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan submit", flag.ContinueOnError)
	pkg := fs.String("package", "", "npm package name (required)")
	version := fs.String("version", "", "package version to install (required)")
	orchestrator := fs.String("orchestrator", "http://127.0.0.1:8443", "orchestrator base URL")
	runner := fs.String("runner", "", "target runner id (default: server picks the first one registered)")
	duration := fs.Duration("duration", 60*time.Second, "max sandbox duration")
	skipValidate := fs.Bool("skip-registry-validate", false, "don't pre-flight verify the package@version against the npm registry (useful for offline tests)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pkg == "" || *version == "" {
		return errors.New("scan submit: -package and -version required")
	}

	// Pre-flight: validate package@version actually exists on the
	// registry. Without this, a typo'd version produces a queued scan
	// that wastes a sandbox just to discover `npm install` will 404.
	if !*skipValidate {
		reg := watcher.NewNPMRegistry()
		if _, err := reg.Resolve(ctx, *pkg, *version); err != nil {
			if errors.Is(err, watcher.ErrPackageNotFound) {
				return fmt.Errorf("scan submit: package %q not found on registry.npmjs.org", *pkg)
			}
			if errors.Is(err, watcher.ErrVersionNotFound) {
				return fmt.Errorf("scan submit: version %q not found for package %q on registry.npmjs.org", *version, *pkg)
			}
			return fmt.Errorf("scan submit: registry lookup failed: %w", err)
		}
	}

	runID, err := a.submitScan(ctx, *orchestrator, *runner, *pkg, *version, *duration)
	if err != nil {
		return err
	}
	return a.reportSubmit(*orchestrator, *pkg, *version, runID)
}

// submitScan packages a scan-submit request and POSTs it to the
// orchestrator. Returns the assigned run_id (hex) on success.
//
// Shared by `fangs scan submit` and the auto-scan triggered by
// `fangs package add`. Both build the same sandbox spec via
// watcher.BuildSandboxScan so manual + autonomous flows produce
// identical artifacts for the same (package, version).
func (a *app) submitScan(ctx context.Context, orchestratorURL, runnerID, pkg, version string, duration time.Duration) (string, error) {
	if runnerID == "" {
		h, _ := os.Hostname()
		runnerID = h
	}
	sb := watcher.BuildSandboxScan(pkg, version)
	job := proto.Job{
		Kind:        "sandbox_scan",
		PackageName: pkg,
		Version:     version,
		// WatchedPaths intentionally empty — the orchestrator stamps
		// its configured defaults (from config/orchestrator.yaml) so
		// CLI + watcher share one source of truth.
		Duration: duration,
		Sandbox:  &sb,
	}
	body, err := json.Marshal(map[string]any{
		"target_runner": runnerID,
		"Job":           job,
	})
	if err != nil {
		return "", err
	}
	url := orchestratorURL + "/v1/scans"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("orchestrator returned %d: %s", resp.StatusCode, string(respBody))
	}
	var parsed struct {
		Queued bool   `json:"queued"`
		RunID  string `json:"run_id"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("decode orchestrator response: %w", err)
	}
	return parsed.RunID, nil
}

// reportSubmit prints the human-friendly success message after a scan
// is queued.
func (a *app) reportSubmit(orchestratorURL, pkg, version, runID string) error {
	if a.asJSON {
		return renderJSON(a.out, map[string]any{
			"queued":  true,
			"run_id":  runID,
			"package": pkg,
			"version": version,
		})
	}
	fmt.Fprintf(a.out, "queued scan run_id=%s package=%s version=%s\n", shortID(runID), pkg, version)
	fmt.Fprintf(a.out, "watch: %s/ui/runs/%s\n", orchestratorURL, runID)
	fmt.Fprintf(a.out, "  or:  fangs run show %s\n", shortID(runID))
	return nil
}
