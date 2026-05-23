// SPDX-License-Identifier: Apache-2.0
package notifier

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

// FileEntry mirrors one webhook target as declared in the optional
// `-notifiers-file`. Operators check this file into their config repo;
// the orchestrator upserts each entry into the DB at boot. CLI-added
// entries (`fangs notifier add`) coexist — the file is additive, not
// authoritative.
type FileEntry struct {
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Template    string            `json:"template"`
	SecretEnv   string            `json:"secret_env,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	MinSeverity string            `json:"min_severity,omitempty"`
	Enabled     *bool             `json:"enabled,omitempty"` // pointer so default-true is honored
}

// LoadFromFile reads a JSON file of FileEntry objects and upserts each
// into the DB. Returns (loaded count, error). The format is intentionally
// plain JSON instead of YAML so we don't pull in a yaml dependency —
// operators wanting yaml can convert with `yq -o json` in their pipeline.
func LoadFromFile(ctx context.Context, store storage.Backend, path string) (int, error) {
	if path == "" {
		return 0, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	// Accept either a top-level array OR a top-level object with
	// `notifiers: [...]` — small kindness for operators who like the
	// structured shape.
	entries := []FileEntry{}
	if strings.TrimSpace(string(raw))[0] == '{' {
		var wrap struct {
			Notifiers []FileEntry `json:"notifiers"`
		}
		if err := json.Unmarshal(raw, &wrap); err != nil {
			return 0, fmt.Errorf("parse %s: %w", path, err)
		}
		entries = wrap.Notifiers
	} else {
		if err := json.Unmarshal(raw, &entries); err != nil {
			return 0, fmt.Errorf("parse %s: %w", path, err)
		}
	}

	for i, e := range entries {
		if e.Name == "" || e.URL == "" || e.Template == "" {
			return 0, fmt.Errorf("%s entry %d: name/url/template are required", path, i)
		}
		enabled := true
		if e.Enabled != nil {
			enabled = *e.Enabled
		}
		var headersJSON string
		if len(e.Headers) > 0 {
			b, err := json.Marshal(e.Headers)
			if err != nil {
				return 0, fmt.Errorf("%s entry %d: marshal headers: %w", path, i, err)
			}
			headersJSON = string(b)
		}
		row := storage.NotifierRow{
			Name:        e.Name,
			URL:         e.URL,
			Template:    e.Template,
			SecretEnv:   e.SecretEnv,
			Headers:     headersJSON,
			MinSeverity: e.MinSeverity,
			Enabled:     enabled,
		}
		if err := store.UpsertNotifier(ctx, row); err != nil {
			return 0, fmt.Errorf("upsert %s: %w", e.Name, err)
		}
	}
	return len(entries), nil
}
