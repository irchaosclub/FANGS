// SPDX-License-Identifier: Apache-2.0
package differ

import (
	"regexp"
	"strings"
)

// NormalizePath canonicalizes volatile path segments so a baseline
// remains stable across runs. Examples:
//
//	/proc/12345/status         -> /proc/<PID>/status
//	/tmp/npm-2156-abc/foo      -> /tmp/<RAND>/foo
//	/var/log/2026-05-22.log    -> /var/log/<DATE>.log
//	/root/.npm/_logs/2026-…-debug-0.log -> /root/.npm/_logs/<DATE>-debug-<N>.log
//	/proc/self/...              -> kept as-is (already stable)
//
// Rules are conservative: only replace patterns we know are volatile.
// Keep order intentional — earlier patterns are more specific.
func NormalizePath(p string) string {
	for _, r := range pathRules {
		p = r.re.ReplaceAllString(p, r.repl)
	}
	return p
}

type pathRule struct {
	re   *regexp.Regexp
	repl string
}

var pathRules = []pathRule{
	// /proc/<pid>/ where pid is a number (not "self")
	{regexp.MustCompile(`^/proc/[0-9]+(/|$)`), "/proc/<PID>$1"},
	// /tmp/<random-prefix>-<digits>... — npm/mktemp style
	{regexp.MustCompile(`^/tmp/[a-zA-Z0-9._-]*-[0-9]{3,}([a-zA-Z0-9._-]*)`), "/tmp/<RAND>"},
	// npm's debug log files: YYYY-MM-DDTHH_MM_SS_mmmZ-debug-N.log
	{regexp.MustCompile(`/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9_]+Z-debug-[0-9]+\.log$`), "/<TIMESTAMP>-debug-<N>.log"},
	// Generic ISO-date filenames: 2026-05-22.log, 2026-05-22.txt
	{regexp.MustCompile(`/[0-9]{4}-[0-9]{2}-[0-9]{2}(\.[a-zA-Z]+)$`), "/<DATE>$1"},
	// cacache content-addressed paths under .npm/_cacache/content-v2/sha256/AA/BB/<rest>
	{regexp.MustCompile(`(/\.npm/_cacache/[^/]+/[a-zA-Z0-9]+)/[a-f0-9]{2}/[a-f0-9]{2}/[a-f0-9]+`), "$1/<SHA256>"},
	// cacache index paths: index-v5/AA/BB/<long-hex>
	{regexp.MustCompile(`(/\.npm/_cacache/index-[^/]+)/[a-f0-9]{2}/[a-f0-9]{2}/[a-f0-9]+`), "$1/<HASH>"},
	// cacache /tmp/<random-hex> staging files — vary per install
	{regexp.MustCompile(`(/\.npm/_cacache/tmp)/[a-f0-9]+`), "$1/<HEX>"},
	// Container hostname-style hex strings as path components
	{regexp.MustCompile(`/[a-f0-9]{12,}(/|$)`), "/<HEX>$1"},
}

// NormalizeDestination canonicalizes "ip:port" forms. IPv6 with brackets,
// zero ports, etc. Currently a no-op stub — IPs are already in canonical
// form coming out of the sensor. Reserved for future CDN-collapsing
// (e.g. all 104.16.*.34 → "cloudflare-CDN") but kept disabled until we
// have allow/cidr config from the operator.
func NormalizeDestination(s string) string {
	return s
}

// NormalizeSNI lowercases the host. RFC 6066 says SNI is case-insensitive.
func NormalizeSNI(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// NormalizeDNS lowercases qname and strips trailing dot.
func NormalizeDNS(qname string) string {
	q := strings.ToLower(strings.TrimSpace(qname))
	q = strings.TrimSuffix(q, ".")
	return q
}

// NormalizeBinaryPath collapses symlink-equivalent paths. Currently
// strips trailing nulls and whitespace; kept lean to avoid hiding
// real PATH-traversal indicators.
func NormalizeBinaryPath(p string) string {
	return strings.TrimSpace(strings.TrimRight(p, "\x00"))
}
