// SPDX-License-Identifier: Apache-2.0
package differ

import "testing"

func TestNormalizePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/proc/12345/status", "/proc/<PID>/status"},
		{"/proc/self/maps", "/proc/self/maps"},
		{"/tmp/npm-2156-abc/foo", "/tmp/<RAND>/foo"},
		{"/root/.npm/_logs/2026-05-22T17_02_24_700Z-debug-0.log", "/root/.npm/_logs/<TIMESTAMP>-debug-<N>.log"},
		{"/var/log/2026-05-22.log", "/var/log/<DATE>.log"},
		{"/usr/local/lib/node_modules/npm/package.json", "/usr/local/lib/node_modules/npm/package.json"},
		{"/etc/passwd", "/etc/passwd"},
		{"/root/.npm/_cacache/content-v2/sha256/ab/cd/abc123def", "/root/.npm/_cacache/content-v2/sha256/<SHA256>"},
		{"/root/.npm/_cacache/index-v5/46/33/b2abd228ca638980cfe42d12d418a89da30648e35d497277d5713e38c7ed", "/root/.npm/_cacache/index-v5/<HASH>"},
		{"/sys/fs/cgroup/abcdef123456789abc/cgroup.procs", "/sys/fs/cgroup/<HEX>/cgroup.procs"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := NormalizePath(tc.in)
			if got != tc.want {
				t.Errorf("NormalizePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeSNI(t *testing.T) {
	cases := map[string]string{
		"Registry.NPMJS.Org": "registry.npmjs.org",
		" api.github.com ":   "api.github.com",
		"":                   "",
	}
	for in, want := range cases {
		if got := NormalizeSNI(in); got != want {
			t.Errorf("NormalizeSNI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeDNS(t *testing.T) {
	cases := map[string]string{
		"Registry.npmjs.org.": "registry.npmjs.org",
		"WWW.GOOGLE.COM":      "www.google.com",
		" example.com ":       "example.com",
	}
	for in, want := range cases {
		if got := NormalizeDNS(in); got != want {
			t.Errorf("NormalizeDNS(%q) = %q, want %q", in, got, want)
		}
	}
}
