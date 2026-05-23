// SPDX-License-Identifier: Apache-2.0
package sensor

import (
	"strings"
	"testing"
	"time"

	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

func TestParseDNSQuestion(t *testing.T) {
	t.Parallel()

	makeQuery := func(name string, qtype uint16) []byte {
		hdr := []byte{
			0x12, 0x34, // ID
			0x01, 0x00, // flags: RD
			0x00, 0x01, // QDCOUNT
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ANCOUNT/NSCOUNT/ARCOUNT
		}
		labels := []byte{}
		for _, lbl := range strings.Split(name, ".") {
			labels = append(labels, byte(len(lbl)))
			labels = append(labels, []byte(lbl)...)
		}
		labels = append(labels, 0x00)
		labels = append(labels, byte(qtype>>8), byte(qtype&0xff), 0x00, 0x01)
		return append(hdr, labels...)
	}

	t.Run("example.com A", func(t *testing.T) {
		t.Parallel()
		name, qtype, err := parseDNSQuestion(makeQuery("example.com", 1))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if name != "example.com" || qtype != 1 {
			t.Fatalf("got name=%q qtype=%d", name, qtype)
		}
	})

	t.Run("registry.npmjs.org AAAA", func(t *testing.T) {
		t.Parallel()
		name, qtype, err := parseDNSQuestion(makeQuery("registry.npmjs.org", 28))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if name != "registry.npmjs.org" || qtype != 28 {
			t.Fatalf("got name=%q qtype=%d", name, qtype)
		}
	})

	t.Run("truncated header rejected", func(t *testing.T) {
		t.Parallel()
		if _, _, err := parseDNSQuestion([]byte{1, 2, 3}); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("qdcount zero rejected", func(t *testing.T) {
		t.Parallel()
		if _, _, err := parseDNSQuestion(make([]byte, 12)); err == nil {
			t.Fatal("expected error for qdcount=0")
		}
	})

	t.Run("compression pointer rejected", func(t *testing.T) {
		t.Parallel()
		buf := append(make([]byte, 12), 0xC0, 0x05)
		buf[5] = 0x01
		if _, _, err := parseDNSQuestion(buf); err == nil {
			t.Fatal("expected error for compression pointer")
		}
	})

	t.Run("oversized label rejected", func(t *testing.T) {
		t.Parallel()
		buf := append(make([]byte, 12), 64)
		buf = append(buf, make([]byte, 64)...)
		buf[5] = 0x01
		if _, _, err := parseDNSQuestion(buf); err == nil {
			t.Fatal("expected error for label length >63")
		}
	})
}

func TestParseClientHelloSNI(t *testing.T) {
	t.Parallel()

	// Build a minimal ClientHello with one extension (server_name) carrying
	// the given hostname.
	build := func(hostname string) []byte {
		// Inner extension data (server_name body):
		//   list_length (2) + name_type (1) + name_length (2) + name
		serverName := []byte{
			0x00, byte(len(hostname) + 3), // server_name_list length
			0x00,                      // name_type = host_name
			0x00, byte(len(hostname)), // hostname length
		}
		serverName = append(serverName, []byte(hostname)...)
		// Wrap as extension: type=0 + len + body
		ext := []byte{
			0x00, 0x00, // ExtensionType = server_name
			0x00, byte(len(serverName)), // ExtensionData length
		}
		ext = append(ext, serverName...)
		// Extensions total length wrapper
		extsLen := []byte{0x00, byte(len(ext))}

		// ClientHello body:
		//   ClientVersion(2) + Random(32) + SessionID(1+0) + CipherSuites(2+2) +
		//   CompressionMethods(1+1) + Extensions(2+ext)
		body := []byte{0x03, 0x03} // TLS 1.2 ClientVersion
		body = append(body, make([]byte, 32)...)
		body = append(body, 0x00)                   // SessionID length 0
		body = append(body, 0x00, 0x02, 0x00, 0x35) // CipherSuites: 1 suite (AES_256_CBC_SHA)
		body = append(body, 0x01, 0x00)             // CompressionMethods: 1 method (null)
		body = append(body, extsLen...)
		body = append(body, ext...)

		// Handshake header: type(1) + length(3 big-endian)
		hsLen := len(body)
		hs := []byte{0x01, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}
		hs = append(hs, body...)

		// Record header: type(1) + version(2) + length(2)
		recLen := len(hs)
		rec := []byte{0x16, 0x03, 0x01, byte(recLen >> 8), byte(recLen)}
		rec = append(rec, hs...)
		return rec
	}

	t.Run("example.com", func(t *testing.T) {
		t.Parallel()
		sni, err := parseClientHelloSNI(build("example.com"))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if sni != "example.com" {
			t.Fatalf("got %q want example.com", sni)
		}
	})

	t.Run("rejects short buffer", func(t *testing.T) {
		t.Parallel()
		if _, err := parseClientHelloSNI([]byte{1, 2, 3}); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("rejects wrong content-type byte", func(t *testing.T) {
		t.Parallel()
		buf := build("example.com")
		buf[0] = 0x17 // ApplicationData, not Handshake
		if _, err := parseClientHelloSNI(buf); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("rejects wrong handshake-type byte", func(t *testing.T) {
		t.Parallel()
		buf := build("example.com")
		buf[5] = 0x02 // ServerHello, not ClientHello
		if _, err := parseClientHelloSNI(buf); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestTLSDedup(t *testing.T) {
	t.Parallel()

	d := newTLSDedup(5 * time.Second)
	now := time.Now()

	// First sighting: no duplicate
	if first := d.observe(1234, "example.com", "libssl", now); first != "" {
		t.Fatalf("first sighting should return empty, got %q", first)
	}

	// Same (pid, sni) within window from different source: tagged
	if first := d.observe(1234, "example.com", "tcp_clienthello", now.Add(time.Millisecond)); first != "libssl" {
		t.Fatalf("second sighting should tag libssl, got %q", first)
	}

	// Different pid: not a duplicate
	if first := d.observe(5678, "example.com", "tcp_clienthello", now.Add(2*time.Millisecond)); first != "" {
		t.Fatalf("different pid should not dedup, got %q", first)
	}

	// Same (pid, sni) past window: not a duplicate anymore
	if first := d.observe(1234, "example.com", "tcp_clienthello", now.Add(10*time.Second)); first != "" {
		t.Fatalf("past-window sighting should not dedup, got %q", first)
	}

	// Empty SNI: dedup is a no-op
	if first := d.observe(1234, "", "libssl", now); first != "" {
		t.Fatalf("empty SNI: dedup should not fire, got %q", first)
	}
}

func TestBuildPathFilterKey(t *testing.T) {
	t.Parallel()

	t.Run("happy path: bits = bytes × 8", func(t *testing.T) {
		t.Parallel()
		k, err := buildPathFilterKey("/etc/")
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if k.PrefixLenBits != uint32(len("/etc/")*8) {
			t.Fatalf("PrefixLenBits: got %d want %d", k.PrefixLenBits, len("/etc/")*8)
		}
		want := append([]byte("/etc/"), make([]byte, proto.PathLen-len("/etc/"))...)
		if string(k.Path[:]) != string(want) {
			t.Fatal("path buffer mismatch")
		}
	})

	t.Run("empty rejected", func(t *testing.T) {
		t.Parallel()
		if _, err := buildPathFilterKey(""); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("oversized rejected", func(t *testing.T) {
		t.Parallel()
		if _, err := buildPathFilterKey(strings.Repeat("x", proto.PathLen+1)); err == nil {
			t.Fatal("expected error")
		}
	})
}
