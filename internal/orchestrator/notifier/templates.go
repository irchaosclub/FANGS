// SPDX-License-Identifier: Apache-2.0
package notifier

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

// renderer turns a run + deviation set into a request body + content
// type. Each built-in template produces JSON that matches the target
// service's expected schema (Slack incoming-webhook, Discord webhook,
// or the FANGS generic envelope).
type renderer func(run storage.Run, devs []storage.DeviationRow) ([]byte, string, error)

var renderers = map[string]renderer{
	"slack":   renderSlack,
	"discord": renderDiscord,
	"generic": renderGeneric,
}

// renderGeneric — the FANGS-native envelope. Operators consume this when
// they're piping into their own SIEM / event bus / Lambda.
func renderGeneric(run storage.Run, devs []storage.DeviationRow) ([]byte, string, error) {
	type devItem struct {
		ID         string `json:"id"`
		Category   string `json:"category"`
		Value      string `json:"value"`
		Severity   string `json:"severity"`
		EvidenceID int64  `json:"evidence_event_id"`
	}
	envelope := struct {
		Source      string    `json:"source"`
		Schema      string    `json:"schema_version"`
		RunID       string    `json:"run_id"`
		PackageName string    `json:"package_name"`
		Version     string    `json:"version"`
		State       string    `json:"state"`
		IsBaseline  bool      `json:"is_baseline"`
		Severity    string    `json:"max_severity"`
		Devs        []devItem `json:"deviations"`
		Count       int       `json:"deviation_count"`
	}{
		Source:      "fangs-orchestrator",
		Schema:      "v1",
		RunID:       run.ID,
		PackageName: run.PackageName,
		Version:     run.Version,
		State:       string(run.State),
		IsBaseline:  run.IsBaseline,
		Severity:    highestSeverity(devs),
		Count:       len(devs),
	}
	envelope.Devs = make([]devItem, 0, len(devs))
	for _, d := range devs {
		envelope.Devs = append(envelope.Devs, devItem{
			ID: d.ID, Category: d.Category, Value: d.Value,
			Severity: d.Severity, EvidenceID: d.EvidenceEventID,
		})
	}
	b, err := json.Marshal(envelope)
	return b, "application/json", err
}

// renderSlack — Slack incoming-webhook payload. Uses blocks for a
// readable card; falls back to a top-level `text` so notifications also
// show in mobile previews.
func renderSlack(run storage.Run, devs []storage.DeviationRow) ([]byte, string, error) {
	maxSev := highestSeverity(devs)
	headerText := fmt.Sprintf("🚨 FANGS deviation: %s@%s — %d finding%s (max: %s)",
		run.PackageName, run.Version, len(devs), plural(len(devs)), maxSev)

	// Top-N findings in the body — Slack messages cap at 40k chars; in
	// practice 10–15 deviations is the realistic ceiling for a run.
	var lines []string
	max := 12
	for i, d := range devs {
		if i >= max {
			lines = append(lines, fmt.Sprintf("_… and %d more_", len(devs)-max))
			break
		}
		lines = append(lines, fmt.Sprintf("• *%s* `%s` — %s",
			d.Severity, truncate(d.Value, 80), d.Category))
	}

	payload := map[string]any{
		"text": headerText, // mobile preview
		"blocks": []any{
			map[string]any{
				"type": "header",
				"text": map[string]any{"type": "plain_text", "text": headerText, "emoji": true},
			},
			map[string]any{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": fmt.Sprintf("Run `%s` · package `%s` · version `%s`",
						shortID(run.ID), run.PackageName, run.Version),
				},
			},
			map[string]any{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": strings.Join(lines, "\n"),
				},
			},
		},
	}
	b, err := json.Marshal(payload)
	return b, "application/json", err
}

// renderDiscord — Discord webhook payload (uses embeds for a card view).
func renderDiscord(run storage.Run, devs []storage.DeviationRow) ([]byte, string, error) {
	maxSev := highestSeverity(devs)
	color := discordColor(maxSev)
	title := fmt.Sprintf("FANGS deviation: %s@%s", run.PackageName, run.Version)

	max := 12
	fields := make([]map[string]any, 0, max+1)
	for i, d := range devs {
		if i >= max {
			fields = append(fields, map[string]any{
				"name":   "…",
				"value":  fmt.Sprintf("and %d more", len(devs)-max),
				"inline": false,
			})
			break
		}
		fields = append(fields, map[string]any{
			"name":   fmt.Sprintf("%s · %s", d.Severity, d.Category),
			"value":  fmt.Sprintf("`%s`", truncate(d.Value, 100)),
			"inline": false,
		})
	}

	embed := map[string]any{
		"title": title,
		"description": fmt.Sprintf("**%d finding%s** (max severity: **%s**)\nRun `%s`",
			len(devs), plural(len(devs)), maxSev, shortID(run.ID)),
		"color":  color,
		"fields": fields,
	}
	payload := map[string]any{
		"username": "FANGS",
		"embeds":   []any{embed},
	}
	b, err := json.Marshal(payload)
	return b, "application/json", err
}

func discordColor(severity string) int {
	switch severity {
	case "critical":
		return 0xE3635D
	case "high":
		return 0xD3A851
	case "medium":
		return 0xD3A851
	case "low":
		return 0x6DA3D8
	}
	return 0x808080
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// parseJSONStringMap — used by parseHeaders. Best-effort: returns nil
// on any unmarshal failure rather than panicking.
func parseJSONStringMap(raw string) map[string]string {
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil
	}
	return m
}
