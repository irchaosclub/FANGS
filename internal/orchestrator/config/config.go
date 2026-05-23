// SPDX-License-Identifier: Apache-2.0
//
// Package config holds the YAML config schema for the orchestrator.
//
// FANGS started as "flags + env vars only" — no config file, no
// mystery format to learn. That ages poorly once operators want to
// edit per-deployment things like the watched-path list. This package
// adds a single optional config file (-config /path/to/orchestrator.yaml)
// that:
//
//   - is OPTIONAL: a fresh checkout with no -config flag still runs
//     with hardcoded defaults
//   - overrides those defaults section-by-section: anything you omit
//     falls back to the hardcoded value
//   - is read once at startup; SIGHUP reload is a future addition
//
// The schema currently exposes only watched_paths because that's what
// operators actually want to edit. Other sections (notifiers,
// retention, watcher cadence) slot in next to it when their flag-based
// versions feel cramped.
package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

// Config is the in-memory representation of orchestrator.yaml. Every
// section is optional; an empty section means "use the hardcoded
// default."
type Config struct {
	// WatchedPaths is the default set the orchestrator stamps onto
	// every job that arrived with an empty WatchedPaths slice (auto-
	// submitted by the watcher, manually submitted via `fangs scan
	// submit` or `fangs package add`). When this section is omitted
	// from the file, watcher.DefaultWatchedPaths() supplies the values.
	WatchedPaths []WatchedPathEntry `yaml:"watched_paths"`

	// Allow holds GLOBAL allowlist entries — IPs, SNIs, and path
	// exclusions — that the Differ uses to suppress noise from the
	// deviation set. Entries here are upserted into the allowlists
	// table at startup with deterministic IDs (so reloads stay
	// idempotent — no duplicate rows). CLI-added entries coexist;
	// removing a config-managed entry via `fangs allow remove` works
	// but it reappears on next restart unless you also delete the
	// YAML line.
	//
	// Per-package scoping is intentionally not in the YAML — that's
	// what `fangs allow add -package P` is for. Config is global only.
	Allow AllowConfig `yaml:"allow"`
}

// AllowConfig groups the three kinds of allowlist entries.
type AllowConfig struct {
	// CIDRs match the kernel-reported destination IP of a net_connect
	// event. Matching connections are dropped from
	// net_new_destination; their identity is still carried by SNI/DNS
	// fingerprints when present. The hardcoded DefaultCDNAllowlist
	// applies underneath — entries here are additive.
	CIDRs []AllowEntry `yaml:"cidrs"`

	// SNIs match the lowercased server-name from TLS ClientHello.
	// Used to suppress legitimate telemetry endpoints from
	// net_new_https_host without affecting per-package baselines.
	SNIs []AllowEntry `yaml:"snis"`

	// Paths suppress file_access fingerprints whose normalized path
	// starts with the given prefix. Use this for noisy-by-design
	// directories nested under a watched prefix — e.g. watch /usr but
	// exclude /usr/lib/ to skip every libc/.so resolution.
	Paths []AllowEntry `yaml:"paths"`
}

// AllowEntry is one config-managed allowlist row. Note is optional;
// it shows up in the UI / `fangs allow list` next to the value to
// explain why an entry exists.
type AllowEntry struct {
	Value string `yaml:"value"`
	Note  string `yaml:"note,omitempty"`
}

// WatchedPathEntry is the YAML-friendly form of proto.WatchedPath.
// The proto type uses Go-natural field names (Prefix, CredTagged);
// the YAML uses snake-case + the shorter `cred` for the bool.
type WatchedPathEntry struct {
	Prefix string `yaml:"prefix"`
	Cred   bool   `yaml:"cred,omitempty"`
}

// AsProto converts a config-side path entry to the wire-shape proto
// the orchestrator + runner understand.
func (e WatchedPathEntry) AsProto() proto.WatchedPath {
	return proto.WatchedPath{Prefix: e.Prefix, CredTagged: e.Cred}
}

// WatchedPathsAsProto builds a fresh []proto.WatchedPath from a config's
// watched_paths section. Returns nil for an empty section so callers
// can fall back to their own default.
func (c *Config) WatchedPathsAsProto() []proto.WatchedPath {
	if c == nil || len(c.WatchedPaths) == 0 {
		return nil
	}
	out := make([]proto.WatchedPath, 0, len(c.WatchedPaths))
	for _, e := range c.WatchedPaths {
		out = append(out, e.AsProto())
	}
	return out
}

// ApplyAllowlist upserts every entry in c.Allow into the storage's
// allowlists table. Idempotent — IDs are derived from sha256(kind+value)
// so the same YAML across restarts always touches the same rows. Logs
// any per-entry errors but doesn't fail the whole apply (a single
// malformed CIDR shouldn't keep the rest from loading).
func (c *Config) ApplyAllowlist(ctx context.Context, store storage.Backend, logger *slog.Logger) error {
	if c == nil || store == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	apply := func(kind storage.AllowKind, entries []AllowEntry) int {
		ok := 0
		for _, e := range entries {
			if e.Value == "" {
				continue
			}
			row := storage.AllowEntry{
				ID:        configEntryID(kind, e.Value),
				Scope:     storage.AllowScopeGlobal,
				Kind:      kind,
				Value:     e.Value,
				Note:      e.Note,
				CreatedAt: time.Now().UTC(),
			}
			if err := store.AddAllowEntry(ctx, row); err != nil {
				// AddAllowEntry's INSERT will fail with conflict on a
				// second startup. Treat that as success — the row is
				// already there with the right (kind, value) and a
				// stable ID we control.
				logger.Debug("config allowlist upsert (already exists, ok)",
					"kind", kind, "value", e.Value, "err", err)
			}
			ok++
		}
		return ok
	}
	nC := apply(storage.AllowKindCIDR, c.Allow.CIDRs)
	nS := apply(storage.AllowKindSNI, c.Allow.SNIs)
	nP := apply(storage.AllowKindPath, c.Allow.Paths)
	if nC+nS+nP > 0 {
		logger.Info("config allowlist applied",
			"cidrs", nC, "snis", nS, "paths", nP)
	}
	return nil
}

// configEntryID derives a deterministic 16-hex-char ID for a config-
// managed allowlist row. Stable across restarts so re-applies don't
// create duplicates; prefixed with "cfg" so an operator browsing the
// DB can tell at a glance which entries came from the YAML.
func configEntryID(kind storage.AllowKind, value string) string {
	h := sha256.Sum256([]byte(string(kind) + "|" + value))
	return "cfg" + hex.EncodeToString(h[:6])
}

// Load parses the YAML file at path. Returns a zero-value Config (NOT
// nil) when path is empty or the file doesn't exist — caller's
// defaults take over for every section in that case.
func Load(path string) (*Config, error) {
	if path == "" {
		return &Config{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &c, nil
}
