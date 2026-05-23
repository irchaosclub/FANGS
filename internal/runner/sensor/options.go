// SPDX-License-Identifier: Apache-2.0
package sensor

import (
	"log/slog"
	"time"

	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

// Options configures the Sensor's long-lived state — eBPF program load,
// probe attach, ringbuf reader. Per-scan state (cgroup id, run id,
// watched paths) is passed to AddCgroup instead.
type Options struct {
	// LibSSLPath, if non-empty, overrides the libssl.so auto-detection used
	// for the TLS SNI uprobe (mechanism 1). Empty means try common paths.
	LibSSLPath string

	// Logger is used for non-event logging (probe attach status, warnings,
	// shutdown summary). If nil, a no-op logger is installed.
	Logger *slog.Logger

	// EnsureTracefs, when true, attempts `mount -t tracefs nodev
	// /sys/kernel/tracing` if it isn't already mounted. cilium/ebpf's
	// tracepoint attach requires tracefs; some minimal distros (WSL2,
	// container images) don't auto-mount it.
	EnsureTracefs bool

	// DedupWindow controls how long a (pid, sni) tuple is remembered for
	// the TLS-source cross-mechanism dedup. Zero disables dedup tagging.
	DedupWindow time.Duration
}

// AddCgroupOptions describes one watched cgroup. Pass to Sensor.AddCgroup.
type AddCgroupOptions struct {
	// CgroupID identifies the cgroupv2 cgroup whose processes' events to
	// capture. Get this from the cgroup directory's inode number.
	CgroupID uint64

	// RunID is stamped into every event emitted while this cgroup is
	// watched. Conventionally a 16-byte ULID.
	RunID [proto.RunIDLen]byte

	// WatchedPaths is the allowlist for file-access events under this
	// cgroup. File events (openat) are emitted ONLY when the opened path
	// starts with one of these prefixes. Exec / connect / DNS / TLS
	// events bypass this filter. At least one entry is required for file
	// events to fire.
	WatchedPaths []WatchedPath
}

// WatchedPath is one entry in the path-allowlist LPM_TRIE. Prefix must be
// absolute (start with '/') and at most proto.PathLen bytes.
type WatchedPath struct {
	Prefix     string
	CredTagged bool // tag matching events with EventTagInteresting|EventTagCredAccess
}
