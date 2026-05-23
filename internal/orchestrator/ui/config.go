// SPDX-License-Identifier: Apache-2.0
package ui

import (
	"net/http"
	"os"
)

// handleConfig renders /ui/config — the operator's view of what the
// orchestrator is currently running with. Read-only; reload requires
// orchestrator restart.
//
// Two sources of truth surfaced:
//   - effectivePaths: the in-memory watched-path slice the orchestrator
//     stamps onto incoming jobs. This is config-merged-with-defaults,
//     so it reflects what's actually in effect, not just what's in the
//     YAML.
//   - The raw YAML file at configPath: shown alongside so operators
//     can sanity-check that what's on disk matches what's loaded.
//     When the file doesn't exist, we report that explicitly instead
//     of just dropping the section.
func (h *Handler) handleConfig(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"WatchedPaths": h.effectivePaths,
		"ConfigPath":   h.configPath,
	}

	if h.configPath != "" {
		if raw, err := os.ReadFile(h.configPath); err == nil {
			data["YAML"] = string(raw)
			data["YAMLExists"] = true
		} else if os.IsNotExist(err) {
			data["YAMLExists"] = false
		} else {
			h.logger.Warn("ui config: read file", "path", h.configPath, "err", err)
			data["YAMLError"] = err.Error()
		}
	}

	// Allowlist context — operators often want to see config-derived
	// entries (cfg-prefixed IDs) alongside the YAML they came from.
	if entries, err := h.store.ListAllowEntries(r.Context()); err == nil {
		data["AllowEntries"] = entries
	}

	h.render(w, "config", data)
}
