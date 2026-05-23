// SPDX-License-Identifier: Apache-2.0
package differ

import (
	"encoding/json"
	"testing"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

// fakeEvent builds an EventRow with marshalled payload — keeps test
// table compact.
func fakeEvent(id int64, evType string, payload any) storage.EventRow {
	b, _ := json.Marshal(payload)
	return storage.EventRow{ID: id, Type: evType, Data: b}
}

func TestExtractFingerprints(t *testing.T) {
	events := []storage.EventRow{
		fakeEvent(1, "file_access", map[string]any{"PathName": "/etc/passwd", "Flags": 0}),
		fakeEvent(2, "file_access", map[string]any{"PathName": "/tmp/test/payload.sh", "Flags": 64}), // O_CREAT
		fakeEvent(3, "file_access", map[string]any{"PathName": "/etc/passwd", "Flags": 0}),           // dup
		fakeEvent(4, "exec", map[string]any{"BinaryPathStr": "/usr/bin/curl"}),
		fakeEvent(5, "net_connect", map[string]any{"DestIP": "1.2.3.4", "DestPort": 31337}),
		fakeEvent(6, "dns_query", map[string]any{"QName": "exfil.attacker.example"}),
		fakeEvent(7, "tls_sni", map[string]any{"SNI": "exfil.attacker.example"}),
	}
	fps := ExtractFingerprints(events)

	byKey := map[string]Fingerprint{}
	for _, fp := range fps {
		byKey[fp.Key()] = fp
	}

	expect := []struct {
		key   string
		count int
		evtID int64
	}{
		{"fs_new_path_read|/etc/passwd", 2, 1},
		{"fs_new_path_write|/tmp/test/payload.sh", 1, 2},
		{"proc_new_exec|/usr/bin/curl", 1, 4},
		{"net_new_destination|1.2.3.4:31337", 1, 5},
		{"net_new_dns|exfil.attacker.example", 1, 6},
		{"net_new_https_host|exfil.attacker.example", 1, 7},
	}
	for _, want := range expect {
		got, ok := byKey[want.key]
		if !ok {
			t.Errorf("expected fingerprint %q not found", want.key)
			continue
		}
		if got.Count != want.count {
			t.Errorf("%q count: got %d, want %d", want.key, got.Count, want.count)
		}
		if got.FirstEvtID != want.evtID {
			t.Errorf("%q FirstEvtID: got %d, want %d", want.key, got.FirstEvtID, want.evtID)
		}
	}
}

func TestExtractFingerprintsAllowlistsCDNs(t *testing.T) {
	// Cloudflare IP on 443 is suppressed (CDN round-robin noise).
	// Non-CDN IP on 443 is FLAGGED (malware-via-HTTPS attack class).
	// Non-CDN IP on weird port is also flagged.
	events := []storage.EventRow{
		fakeEvent(1, "net_connect", map[string]any{"DestIP": "104.16.8.34", "DestPort": 443}),  // Cloudflare — suppress
		fakeEvent(2, "net_connect", map[string]any{"DestIP": "140.82.114.6", "DestPort": 443}), // GitHub — suppress
		fakeEvent(3, "net_connect", map[string]any{"DestIP": "1.2.3.4", "DestPort": 443}),      // Random IP on 443 — KEEP
		fakeEvent(4, "net_connect", map[string]any{"DestIP": "5.6.7.8", "DestPort": 31337}),    // Weird port — KEEP
	}
	fps := ExtractFingerprints(events)
	got := map[string]bool{}
	for _, fp := range fps {
		got[fp.Value] = true
	}
	if !got["1.2.3.4:443"] {
		t.Errorf("non-CDN IP on 443 should be flagged (malware-via-HTTPS attack class)")
	}
	if !got["5.6.7.8:31337"] {
		t.Errorf("non-standard-port destination should be flagged")
	}
	if got["104.16.8.34:443"] {
		t.Errorf("Cloudflare IP on 443 should be suppressed via CDN allowlist")
	}
	if got["140.82.114.6:443"] {
		t.Errorf("GitHub IP on 443 should be suppressed via CDN allowlist")
	}
}

func TestIsAllowlistedCDN(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"104.16.8.34", true},     // Cloudflare
		{"140.82.114.6", true},    // GitHub
		{"142.250.190.78", true},  // Google
		{"199.232.45.10", true},   // Fastly
		{"1.2.3.4", false},        // Random
		{"1.1.1.1", false},        // Cloudflare DNS resolver — NOT in CDN allowlist intentionally
		{"10.255.255.254", false}, // Docker bridge DNS
		{"", false},
		{"not-an-ip", false},
	}
	for _, tc := range cases {
		if got := IsAllowlistedCDN(tc.ip); got != tc.want {
			t.Errorf("IsAllowlistedCDN(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestExtractFingerprintsSkipsEmpty(t *testing.T) {
	events := []storage.EventRow{
		fakeEvent(1, "file_access", map[string]any{"PathName": "", "Flags": 0}),
		fakeEvent(2, "net_connect", map[string]any{"DestIP": "", "DestPort": 443}),
		fakeEvent(3, "dns_query", map[string]any{"QName": ""}),
	}
	fps := ExtractFingerprints(events)
	if len(fps) != 0 {
		t.Errorf("expected 0 fingerprints, got %d: %+v", len(fps), fps)
	}
}
