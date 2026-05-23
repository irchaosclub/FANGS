// SPDX-License-Identifier: Apache-2.0
package differ

import (
	"log/slog"
	"net"
	"strings"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

// Filter applies operator allowlist rules (CIDR / path-prefix / SNI) on
// top of the hardcoded DefaultCDNAllowlist. It's built per-run by the
// Differ from the union of global and package-scoped storage.AllowEntry
// rows and then queried by the fingerprint extractors to suppress
// known-benign destinations.
//
// Goals:
//   - Operators can carve out their internal infra ("we always talk to
//     telemetry.internal") without editing source.
//   - Per-package carve-outs let one noisy package's quirk not affect
//     baselines of others.
//   - The default CDN list still applies even when the DB is empty.
type Filter struct {
	cidrs []*net.IPNet
	paths []string
	snis  map[string]struct{} // lowercased
}

// NewFilter builds a Filter from operator allowlist entries plus the
// hardcoded DefaultCDNAllowlist. Invalid entries are logged + skipped.
func NewFilter(entries []storage.AllowEntry, logger *slog.Logger) *Filter {
	if logger == nil {
		logger = slog.Default()
	}
	f := &Filter{
		snis: make(map[string]struct{}),
	}
	// Hardcoded CDN ranges first.
	for _, c := range DefaultCDNAllowlist {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			f.cidrs = append(f.cidrs, n)
		}
	}
	// Then operator entries.
	for _, e := range entries {
		switch e.Kind {
		case storage.AllowKindCIDR:
			_, n, err := net.ParseCIDR(e.Value)
			if err != nil {
				logger.Warn("allowlist cidr invalid", "id", e.ID, "value", e.Value, "err", err)
				continue
			}
			f.cidrs = append(f.cidrs, n)
		case storage.AllowKindPath:
			if e.Value != "" {
				f.paths = append(f.paths, e.Value)
			}
		case storage.AllowKindSNI:
			if e.Value != "" {
				f.snis[strings.ToLower(strings.TrimSpace(e.Value))] = struct{}{}
			}
		}
	}
	return f
}

// SuppressIP reports whether ipStr should be dropped from
// net_new_destination — either it's in the hardcoded CDN ranges, or an
// operator added an explicit CIDR carve-out.
func (f *Filter) SuppressIP(ipStr string) bool {
	if f == nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range f.cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// SuppressPath reports whether p (already-normalized) starts with any
// allowed path prefix.
func (f *Filter) SuppressPath(p string) bool {
	if f == nil {
		return false
	}
	for _, prefix := range f.paths {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// SuppressSNI reports whether the normalized SNI is explicitly allowed.
func (f *Filter) SuppressSNI(sni string) bool {
	if f == nil {
		return false
	}
	_, ok := f.snis[strings.ToLower(strings.TrimSpace(sni))]
	return ok
}
