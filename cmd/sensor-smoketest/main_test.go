// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

func TestParseOrGenerateRunID(t *testing.T) {
	t.Parallel()

	t.Run("empty input generates non-zero id", func(t *testing.T) {
		t.Parallel()
		id, err := parseOrGenerateRunID("")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		var zero [proto.RunIDLen]byte
		if id == zero {
			t.Fatalf("expected non-zero synthetic id, got %x", id)
		}
	})

	t.Run("valid 32-hex input parses exactly", func(t *testing.T) {
		t.Parallel()
		hexStr := "0102030405060708090a0b0c0d0e0f10"
		id, err := parseOrGenerateRunID(hexStr)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		got := hex.EncodeToString(id[:])
		if got != hexStr {
			t.Fatalf("round-trip mismatch: got %s want %s", got, hexStr)
		}
	})

	t.Run("wrong length rejected", func(t *testing.T) {
		t.Parallel()
		for name, hexStr := range map[string]string{
			"too short": "0102030405",
			"too long":  "0102030405060708090a0b0c0d0e0f1011",
		} {
			name, hexStr := name, hexStr
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				if _, err := parseOrGenerateRunID(hexStr); err == nil {
					t.Fatalf("expected error for %q, got nil", hexStr)
				}
			})
		}
	})

	t.Run("non-hex rejected", func(t *testing.T) {
		t.Parallel()
		if _, err := parseOrGenerateRunID("nothex_____________________xx_zz"); err == nil {
			t.Fatal("expected error for non-hex input")
		}
	})
}

func TestWatchListSet(t *testing.T) {
	t.Parallel()

	t.Run("plain prefix", func(t *testing.T) {
		t.Parallel()
		var w watchList
		if err := w.Set("/etc/"); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if len(w) != 1 {
			t.Fatalf("len: got %d want 1", len(w))
		}
		if w[0].Prefix != "/etc/" || w[0].CredTagged {
			t.Errorf("got %+v", w[0])
		}
	})

	t.Run("@cred suffix flips action", func(t *testing.T) {
		t.Parallel()
		var w watchList
		if err := w.Set("/root/.aws/@cred"); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if w[0].Prefix != "/root/.aws/" || !w[0].CredTagged {
			t.Errorf("got %+v", w[0])
		}
	})

	t.Run("repeatable", func(t *testing.T) {
		t.Parallel()
		var w watchList
		for _, v := range []string{"/etc/", "/home/", "/tmp/"} {
			if err := w.Set(v); err != nil {
				t.Fatalf("Set(%q): %v", v, err)
			}
		}
		if len(w) != 3 {
			t.Fatalf("len: got %d want 3", len(w))
		}
	})

	t.Run("rejects relative path", func(t *testing.T) {
		t.Parallel()
		var w watchList
		if err := w.Set("etc/"); err == nil {
			t.Fatal("expected error for relative path")
		}
	})

	t.Run("rejects empty", func(t *testing.T) {
		t.Parallel()
		var w watchList
		if err := w.Set(""); err == nil {
			t.Fatal("expected error for empty")
		}
	})

	t.Run("rejects overly long prefix", func(t *testing.T) {
		t.Parallel()
		var w watchList
		long := "/" + strings.Repeat("a", proto.PathLen)
		if err := w.Set(long); err == nil {
			t.Fatalf("expected error for prefix length %d", len(long))
		}
	})
}

func TestCstring(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		in   []byte
		want string
	}{
		"empty":          {[]byte{}, ""},
		"all NUL":        {[]byte{0, 0, 0}, ""},
		"NUL terminated": {[]byte("foo\x00\x00bar"), "foo"},
		"no NUL":         {[]byte("nonull"), "nonull"},
		"NUL at zero":    {[]byte{0, 'a'}, ""},
	} {
		name, c := name, c
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := cstring(c.in); got != c.want {
				t.Fatalf("cstring(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestFamilyString(t *testing.T) {
	t.Parallel()
	for in, want := range map[uint8]string{
		proto.AFInet:  "ipv4",
		proto.AFInet6: "ipv6",
		99:            "family_99",
	} {
		if got := familyString(in); got != want {
			t.Errorf("familyString(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatIP(t *testing.T) {
	t.Parallel()

	t.Run("ipv4", func(t *testing.T) {
		t.Parallel()
		addr := make([]byte, 16)
		addr[0], addr[1], addr[2], addr[3] = 1, 2, 3, 4
		if got := formatIP(proto.AFInet, addr); got != "1.2.3.4" {
			t.Errorf("ipv4: got %q want 1.2.3.4", got)
		}
	})

	t.Run("ipv6 loopback ::1", func(t *testing.T) {
		t.Parallel()
		addr := make([]byte, 16)
		addr[15] = 1
		if got := formatIP(proto.AFInet6, addr); got != "0:0:0:0:0:0:0:1" {
			t.Errorf("ipv6: got %q want 0:0:0:0:0:0:0:1", got)
		}
	})

	t.Run("ipv4 short buffer returns empty", func(t *testing.T) {
		t.Parallel()
		if got := formatIP(proto.AFInet, []byte{1, 2}); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})

	t.Run("unknown family returns empty", func(t *testing.T) {
		t.Parallel()
		if got := formatIP(99, make([]byte, 16)); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})
}

func TestDecodeTags(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		in   uint8
		want []string
	}{
		"none":             {0, nil},
		"interesting only": {proto.EventTagInteresting, []string{"interesting"}},
		"cred only":        {proto.EventTagCredAccess, []string{"cred_access"}},
		"both":             {proto.EventTagInteresting | proto.EventTagCredAccess, []string{"interesting", "cred_access"}},
	} {
		name, c := name, c
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := decodeTags(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("len: got %d want %d", len(got), len(c.want))
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("[%d]: got %q want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}
