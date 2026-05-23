// SPDX-License-Identifier: Apache-2.0
//
// Package sandbox spawns and manages per-scan containers that host the
// workload being observed. The runner asks the driver to Launch a
// Sandbox from a SandboxSpec; the resulting Handle exposes the
// container's cgroup id (for the sensor to attach to), a Wait channel
// (for completion signaling), and a Stop method (for teardown).
//
// The Docker driver is the only implementation today, but the interface
// is intentionally minimal so a containerd / podman / firecracker
// backend can land later without touching the runner glue.
package sandbox

import (
	"context"
	"errors"
	"time"

	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

// Driver creates and supervises sandbox containers.
type Driver interface {
	Launch(ctx context.Context, spec proto.SandboxSpec) (Handle, error)
}

// Handle is the runner's view of a running sandbox. It is created by
// Driver.Launch and torn down via Stop. CgroupID is the kernel-level
// identifier (inode of the cgroup directory) that the sensor's CGMAP
// uses to filter events to this container's processes.
type Handle interface {
	CgroupID() uint64
	ContainerID() string
	ImageDigest() string
	Wait() <-chan WaitResult
	Stop(ctx context.Context) error
}

// WaitResult is published on Handle.Wait when the container exits.
type WaitResult struct {
	ExitCode  int
	OOMKilled bool
	Err       error
}

// Errors surfaced by drivers.
var (
	ErrImageRequired     = errors.New("sandbox: SandboxSpec.Image is required")
	ErrDaemonUnreachable = errors.New("sandbox: docker daemon unreachable (check /var/run/docker.sock permissions)")
	ErrLaunchTimeout     = errors.New("sandbox: container did not enter Running state before deadline")
)

// Defaults applied to SandboxSpec zero values inside the driver. Kept
// in one place so tests can assert them.
const (
	DefaultMemoryBytes = 512 * 1024 * 1024
	DefaultNanoCPUs    = 1_000_000_000
	DefaultPidsLimit   = 256
	DefaultGracePeriod = 0
	DefaultNetworkMode = "bridge"
	DefaultPullPolicy  = "missing"
	DefaultUser        = "1000:1000"
	DefaultStopTimeout = 5 * time.Second
)

// FilledSpec returns spec with zero-value fields replaced by safe
// defaults. The original spec is not modified.
func FilledSpec(in proto.SandboxSpec) proto.SandboxSpec {
	out := in
	if out.MemoryBytes == 0 {
		out.MemoryBytes = DefaultMemoryBytes
	}
	if out.NanoCPUs == 0 {
		out.NanoCPUs = DefaultNanoCPUs
	}
	if out.PidsLimit == 0 {
		out.PidsLimit = DefaultPidsLimit
	}
	if out.NetworkMode == "" {
		out.NetworkMode = DefaultNetworkMode
	}
	if out.PullPolicy == "" {
		out.PullPolicy = DefaultPullPolicy
	}
	if out.User == "" {
		out.User = DefaultUser
	}
	return out
}
