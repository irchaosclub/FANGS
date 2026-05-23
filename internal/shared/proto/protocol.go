// SPDX-License-Identifier: Apache-2.0
//
// Wire types for the orchestrator <-> runner HTTPS protocol.
//
// Endpoint summary (versioned under /v1/):
//
//	POST /v1/runners/register        runner introduces itself
//	GET  /v1/runners/{id}/jobs       runner long-polls for work (returns 204 if none)
//	POST /v1/runs/{run_id}/events    runner streams captured events back
//	POST /v1/scans                   operator queues a scan (smoke-test-style)
//	GET  /v1/health                  liveness
//
// All bodies are JSON unless noted. Times are RFC 3339 strings.
package proto

import "time"

// RunnerRegistration is the body of POST /v1/runners/register.
// The runner identifies itself once at startup and learns the heartbeat
// interval / scan-poll interval the orchestrator expects.
type RunnerRegistration struct {
	RunnerID      string   `json:"runner_id"` // operator-supplied stable id (default: hostname)
	Hostname      string   `json:"hostname"`
	Capabilities  []string `json:"capabilities"`   // e.g. ["sensor", "sandbox.docker"]
	KernelVersion string   `json:"kernel_version"` // uname -r
	ProtoVersion  uint32   `json:"proto_version"`  // for negotiation; this revision == 1
}

// RegistrationAck is the response to RunnerRegistration.
type RegistrationAck struct {
	OK                bool          `json:"ok"`
	OrchestratorID    string        `json:"orchestrator_id"`
	JobPollInterval   time.Duration `json:"job_poll_interval"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
}

// Heartbeat is the body of POST /v1/runners/{id}/heartbeat. The runner
// sends one every HeartbeatInterval; the orchestrator updates the
// corresponding runner's LastSeen and prunes registrations that haven't
// pinged for ~3× the interval. ActiveRunID + Status are optional —
// included when the runner has a job in flight so the orchestrator's
// UI can show "what's running where" without polling separately.
type Heartbeat struct {
	RunnerID     string `json:"runner_id"`
	ActiveRunID  string `json:"active_run_id,omitempty"` // hex; "" when idle
	Status       string `json:"status,omitempty"`        // "idle"|"running"|"draining"
	EventsQueued int    `json:"events_queued,omitempty"` // depth of the runner's outbound buffer
}

// HeartbeatAck — minimal response so the runner can detect "you're not
// registered anymore" (orchestrator restart, eviction, etc.) and
// re-register without operator intervention.
type HeartbeatAck struct {
	OK            bool `json:"ok"`
	UnknownRunner bool `json:"unknown_runner,omitempty"`
}

// Job is what GET /v1/runners/{id}/jobs returns when work is available.
// Empty response body (204 No Content) means no work; the runner polls
// again after JobPollInterval.
//
// Two job shapes are supported:
//
//   - Kind=="sensor_only": runner attaches the sensor to CgroupPath directly.
//     Used by the smoke-test path where the operator has already prepared
//     a target cgroup.
//   - Kind=="sandbox_scan": runner uses Sandbox to spawn a fresh container,
//     resolves ITS cgroup, attaches the sensor to that. CgroupPath is ignored.
type Job struct {
	RunID        [16]byte      `json:"run_id"`
	Kind         string        `json:"kind"`
	PackageName  string        `json:"package_name,omitempty"` // baseline-keying identifier (e.g. "art-template")
	Version      string        `json:"version,omitempty"`      // package version under test
	CgroupPath   string        `json:"cgroup_path,omitempty"`
	WatchedPaths []WatchedPath `json:"watched_paths"`
	Duration     time.Duration `json:"duration"`
	DispatchedAt time.Time     `json:"dispatched_at"`
	Sandbox      *SandboxSpec  `json:"sandbox,omitempty"`
}

// SandboxSpec describes a per-scan container that the runner spawns to
// host the workload being observed. All fields are optional except
// Image. Zero-value fields fall back to safe defaults inside the driver.
type SandboxSpec struct {
	Image       string            `json:"image"`
	Command     []string          `json:"command,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	WorkingDir  string            `json:"working_dir,omitempty"`
	User        string            `json:"user,omitempty"`
	NetworkMode string            `json:"network_mode,omitempty"`
	MemoryBytes int64             `json:"memory_bytes,omitempty"`
	NanoCPUs    int64             `json:"nano_cpus,omitempty"`
	PidsLimit   int64             `json:"pids_limit,omitempty"`
	PullPolicy  string            `json:"pull_policy,omitempty"`
	GracePeriod time.Duration     `json:"grace_period,omitempty"`
	// CgroupParent is set by the runner (not by the operator) to nest
	// the container under a FANGS-managed parent cgroup whose inode is
	// pre-registered in CGMAP. Closes the sensor-attach race window.
	CgroupParent string `json:"cgroup_parent,omitempty"`
}

// WatchedPath is the protocol-level twin of sensor.WatchedPath (they're
// kept in separate packages so the protocol doesn't depend on the sensor
// implementation).
type WatchedPath struct {
	Prefix     string `json:"prefix"`
	CredTagged bool   `json:"cred_tagged,omitempty"`
}

// EventBatch is one POST body to /v1/runs/{run_id}/events. Bodies are
// streamed: many EventBatch JSON objects, one per line, in a single HTTP
// request. Seq increments monotonically per run; the orchestrator dedups
// on (run_id, seq).
type EventBatch struct {
	RunID  [16]byte        `json:"run_id"`
	Seq    uint64          `json:"seq"`
	Events []EventEnvelope `json:"events"`
}

// EventEnvelope is a single typed sensor event. EventType picks the
// concrete shape carried in Payload; the orchestrator decodes based on
// EventType.
type EventEnvelope struct {
	Type    EventType `json:"type"`
	Payload any       `json:"payload"`
}

// ScanResult is the runner's final report once a Job completes (POST
// /v1/runs/{run_id}/result). The body is empty if successful; "reason"
// carries the failure mode otherwise.
type ScanResult struct {
	RunID         [16]byte      `json:"run_id"`
	Status        string        `json:"status"` // "ok" | "failed" | "timeout"
	Reason        string        `json:"reason,omitempty"`
	EventsEmitted int64         `json:"events_emitted"`
	EventsDropped uint64        `json:"events_dropped"`
	Duration      time.Duration `json:"duration"`
}

// HealthResponse is the body of GET /v1/health. Liveness probe target.
type HealthResponse struct {
	Status         string `json:"status"` // "ok"
	OrchestratorID string `json:"orchestrator_id"`
	Version        string `json:"version"`
}

// CurrentProtoVersion is the protocol revision implemented by this package.
// Runners and orchestrators check this on register.
const CurrentProtoVersion uint32 = 1
