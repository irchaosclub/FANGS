// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

func (a *app) notifierCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("notifier: expected subcommand (list|add|remove|test|history)")
	}
	switch args[0] {
	case "list":
		return a.notifierList(ctx, args[1:])
	case "add":
		return a.notifierAdd(ctx, args[1:])
	case "remove", "rm":
		return a.notifierRemove(ctx, args[1:])
	case "test":
		return a.notifierTest(ctx, args[1:])
	case "history":
		return a.notifierHistory(ctx, args[1:])
	default:
		return fmt.Errorf("notifier: unknown subcommand %q", args[0])
	}
}

func (a *app) notifierList(ctx context.Context, _ []string) error {
	rows, err := a.store.ListNotifiers(ctx)
	if err != nil {
		return err
	}
	if a.asJSON {
		return renderJSON(a.out, rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(a.out, "no notifiers configured. add one:")
		fmt.Fprintln(a.out, "  fangs notifier add -name soc-slack -url https://hooks.slack.com/... -template slack")
		return nil
	}
	headers := []string{"NAME", "TEMPLATE", "URL", "ENABLED", "MIN_SEV", "HMAC", "UPDATED"}
	rowsT := make([][]string, 0, len(rows))
	for _, n := range rows {
		hmac := "no"
		if n.SecretEnv != "" {
			hmac = "$" + n.SecretEnv
		}
		enabled := "yes"
		if !n.Enabled {
			enabled = "no"
		}
		sev := n.MinSeverity
		if sev == "" {
			sev = "any"
		}
		rowsT = append(rowsT, []string{n.Name, n.Template, truncate(n.URL, 50), enabled, sev, hmac, n.UpdatedAt.Format(time.RFC3339)})
	}
	renderTable(a.out, headers, rowsT)
	return nil
}

func (a *app) notifierAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("notifier add", flag.ContinueOnError)
	name := fs.String("name", "", "unique identifier for this target (required)")
	url := fs.String("url", "", "webhook URL (required; https://... in production)")
	tmpl := fs.String("template", "generic", "template: slack | discord | generic")
	secretEnv := fs.String("secret-env", "", "env var name holding the HMAC secret (generic only)")
	minSev := fs.String("min-severity", "", "fire only when at least one deviation has severity >= S (low|medium|high|critical)")
	headers := fs.String("headers", "", "extra request headers as JSON object, e.g. '{\"X-API-Key\":\"$KEY\"}'")
	enabled := fs.Bool("enabled", true, "enable the target immediately")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *url == "" {
		return errors.New("notifier add: -name and -url required")
	}
	if _, ok := map[string]bool{"slack": true, "discord": true, "generic": true}[*tmpl]; !ok {
		return fmt.Errorf("notifier add: unknown -template %q (slack|discord|generic)", *tmpl)
	}
	if *minSev != "" {
		if _, ok := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}[*minSev]; !ok {
			return fmt.Errorf("notifier add: invalid -min-severity %q", *minSev)
		}
	}
	if *headers != "" {
		var probe map[string]string
		if err := json.Unmarshal([]byte(*headers), &probe); err != nil {
			return fmt.Errorf("notifier add: -headers isn't a valid JSON string-map: %w", err)
		}
	}
	if err := a.store.UpsertNotifier(ctx, storage.NotifierRow{
		Name:        *name,
		URL:         *url,
		Template:    *tmpl,
		SecretEnv:   *secretEnv,
		Headers:     *headers,
		MinSeverity: *minSev,
		Enabled:     *enabled,
	}); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "notifier %q saved\n", *name)
	return nil
}

func (a *app) notifierRemove(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("notifier remove: expected <name>")
	}
	if err := a.store.DeleteNotifier(ctx, args[0]); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "notifier %q removed\n", args[0])
	return nil
}

func (a *app) notifierTest(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("notifier test: expected <name>")
	}
	target, err := a.store.GetNotifier(ctx, args[0])
	if err != nil {
		return fmt.Errorf("notifier test: %w", err)
	}
	body, contentType, err := buildTestPayload(target.Template)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "fangs-cli (notifier test)")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notifier test: POST failed: %w", err)
	}
	defer resp.Body.Close()
	fmt.Fprintf(a.out, "→ POST %s\n  HTTP %d\n", target.URL, resp.StatusCode)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Fprintln(a.out, "✓ test notification accepted")
		return nil
	}
	return fmt.Errorf("test notification rejected with HTTP %d", resp.StatusCode)
}

func (a *app) notifierHistory(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("notifier history", flag.ContinueOnError)
	runID := fs.String("run", "", "run id (full or prefix); required")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *runID == "" {
		return errors.New("notifier history: -run required")
	}
	run, err := a.store.GetRun(ctx, *runID)
	if errors.Is(err, storage.ErrNotFound) {
		run, err = a.store.ResolveRunPrefix(ctx, *runID)
	}
	if err != nil {
		return err
	}
	rows, err := a.store.ListNotificationsByRun(ctx, run.ID)
	if err != nil {
		return err
	}
	if a.asJSON {
		return renderJSON(a.out, rows)
	}
	if len(rows) == 0 {
		fmt.Fprintf(a.out, "no notification attempts recorded for run %s\n", shortID(run.ID))
		return nil
	}
	headers := []string{"NOTIFIER", "ATTEMPT", "STATUS", "HTTP", "DEVS", "LAST_AT", "ERROR"}
	rowsT := make([][]string, 0, len(rows))
	for _, n := range rows {
		last := "—"
		if n.LastAttemptedAt != nil {
			last = n.LastAttemptedAt.Format(time.RFC3339)
		}
		code := "—"
		if n.ResponseCode > 0 {
			code = fmt.Sprintf("%d", n.ResponseCode)
		}
		rowsT = append(rowsT, []string{
			n.NotifierName, fmt.Sprintf("%d", n.Attempt), n.Status, code,
			fmt.Sprintf("%d", n.DeviationCount), last, truncate(n.ErrorMsg, 40),
		})
	}
	renderTable(a.out, headers, rowsT)
	return nil
}

// buildTestPayload returns a synthetic payload matching the target's
// template — used by `fangs notifier test`. Not HMAC-signed.
func buildTestPayload(template string) (body string, contentType string, err error) {
	switch template {
	case "slack":
		return `{"text":"FANGS notifier test — if you see this, your Slack webhook is wired correctly."}`, "application/json", nil
	case "discord":
		return `{"username":"FANGS","embeds":[{"title":"FANGS notifier test","description":"If you see this, your Discord webhook is wired correctly.","color":6266213}]}`, "application/json", nil
	case "generic":
		return `{"source":"fangs-orchestrator","schema_version":"v1","test":true,"message":"notifier test from fangs CLI"}`, "application/json", nil
	}
	return "", "", fmt.Errorf("unknown template %q", template)
}
