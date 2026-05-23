// SPDX-License-Identifier: Apache-2.0
package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

func TestFilledSpecAppliesDefaults(t *testing.T) {
	in := proto.SandboxSpec{Image: "node:20-slim"}
	out := FilledSpec(in)

	if out.NetworkMode != DefaultNetworkMode {
		t.Errorf("NetworkMode default: got %q, want %q", out.NetworkMode, DefaultNetworkMode)
	}
	if out.MemoryBytes != DefaultMemoryBytes {
		t.Errorf("MemoryBytes default: got %d, want %d", out.MemoryBytes, DefaultMemoryBytes)
	}
	if out.NanoCPUs != DefaultNanoCPUs {
		t.Errorf("NanoCPUs default: got %d, want %d", out.NanoCPUs, DefaultNanoCPUs)
	}
	if out.PidsLimit != DefaultPidsLimit {
		t.Errorf("PidsLimit default: got %d, want %d", out.PidsLimit, DefaultPidsLimit)
	}
	if out.PullPolicy != DefaultPullPolicy {
		t.Errorf("PullPolicy default: got %q, want %q", out.PullPolicy, DefaultPullPolicy)
	}
	if out.User != DefaultUser {
		t.Errorf("User default: got %q, want %q", out.User, DefaultUser)
	}
}

func TestFilledSpecPreservesNonZeroFields(t *testing.T) {
	in := proto.SandboxSpec{
		Image:       "node:20-slim",
		NetworkMode: "none",
		MemoryBytes: 1 << 30,
		User:        "0:0",
		PidsLimit:   1024,
	}
	out := FilledSpec(in)
	if out.NetworkMode != "none" {
		t.Errorf("NetworkMode overridden: got %q", out.NetworkMode)
	}
	if out.MemoryBytes != 1<<30 {
		t.Errorf("MemoryBytes overridden: got %d", out.MemoryBytes)
	}
	if out.User != "0:0" {
		t.Errorf("User overridden: got %q", out.User)
	}
	if out.PidsLimit != 1024 {
		t.Errorf("PidsLimit overridden: got %d", out.PidsLimit)
	}
}

func TestSplitImageTag(t *testing.T) {
	cases := []struct {
		in       string
		wantRepo string
		wantTag  string
	}{
		{"node:20-slim", "node", "20-slim"},
		{"node", "node", "latest"},
		{"library/node:18", "library/node", "18"},
		{"registry.local:5000/app:dev", "registry.local:5000/app", "dev"},
		{"registry.local:5000/app", "registry.local:5000/app", "latest"},
		{"alpine@sha256:abc", "alpine", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			repo, tag := splitImageTag(tc.in)
			if repo != tc.wantRepo || tag != tc.wantTag {
				t.Errorf("splitImageTag(%q) = (%q,%q), want (%q,%q)", tc.in, repo, tag, tc.wantRepo, tc.wantTag)
			}
		})
	}
}

func TestParseCgroupReaderV2(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		err  bool
	}{
		{
			name: "docker scope",
			in:   "0::/system.slice/docker-abc123.scope\n",
			want: "/system.slice/docker-abc123.scope",
		},
		{
			name: "root cgroup",
			in:   "0::/\n",
			want: "/",
		},
		{
			name: "v1 hybrid with unified",
			in:   "12:cpu,cpuacct:/docker/abc\n11:memory:/docker/abc\n0::/system.slice/docker-abc.scope\n",
			want: "/system.slice/docker-abc.scope",
		},
		{
			name: "no unified line",
			in:   "12:cpu,cpuacct:/docker/abc\n11:memory:/docker/abc\n",
			err:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := bufio.NewScanner(strings.NewReader(tc.in))
			got, err := parseCgroupReader(sc)
			if tc.err {
				if err == nil {
					t.Errorf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBuildCreatePayloadHardening pins the security-relevant fields in
// the Docker /containers/create payload. If anyone ever loosens these,
// the tests fail.
func TestBuildCreatePayloadHardening(t *testing.T) {
	spec := FilledSpec(proto.SandboxSpec{
		Image:       "node:20-slim",
		NetworkMode: "bridge",
	})
	body := buildCreatePayload(spec, "node@sha256:deadbeef")

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}

	if got := payload["Image"]; got != "node@sha256:deadbeef" {
		t.Errorf("Image not pinned to digest: got %v", got)
	}
	if got := payload["User"]; got != DefaultUser {
		t.Errorf("User not set to non-root default: got %v", got)
	}

	host, ok := payload["HostConfig"].(map[string]any)
	if !ok {
		t.Fatalf("HostConfig missing or wrong type")
	}

	capDrop, _ := host["CapDrop"].([]any)
	if len(capDrop) != 1 || capDrop[0] != "ALL" {
		t.Errorf("CapDrop != [ALL]: got %v", capDrop)
	}
	sec, _ := host["SecurityOpt"].([]any)
	foundNNP := false
	for _, v := range sec {
		if v == "no-new-privileges:true" {
			foundNNP = true
		}
	}
	if !foundNNP {
		t.Errorf("SecurityOpt missing no-new-privileges:true: got %v", sec)
	}
	if host["NetworkMode"] != "bridge" {
		t.Errorf("NetworkMode wrong: got %v", host["NetworkMode"])
	}
	if host["PidMode"] != "" {
		t.Errorf("PidMode should be empty (no host PID share): got %v", host["PidMode"])
	}
	if got := host["PidsLimit"]; toFloat(got) != float64(DefaultPidsLimit) {
		t.Errorf("PidsLimit != default: got %v", got)
	}
	if got := host["Memory"]; toFloat(got) != float64(DefaultMemoryBytes) {
		t.Errorf("Memory != default: got %v", got)
	}
	if _, ok := host["Tmpfs"]; !ok {
		t.Errorf("Tmpfs not configured")
	}
	if _, ok := host["LogConfig"]; !ok {
		t.Errorf("LogConfig not configured")
	}
}

func TestBuildCreatePayloadNetworkNone(t *testing.T) {
	spec := FilledSpec(proto.SandboxSpec{
		Image:       "node:20-slim",
		NetworkMode: "none",
	})
	body := buildCreatePayload(spec, "")
	var payload map[string]any
	_ = json.Unmarshal(body, &payload)
	host := payload["HostConfig"].(map[string]any)
	if host["NetworkMode"] != "none" {
		t.Errorf("NetworkMode=none not propagated: got %v", host["NetworkMode"])
	}
}

func TestDockerDriverRejectsEmptyImage(t *testing.T) {
	d := NewDockerDriver(DockerOptions{})
	_, err := d.Launch(context.Background(), proto.SandboxSpec{})
	if !errors.Is(err, ErrImageRequired) {
		t.Errorf("want ErrImageRequired, got %v", err)
	}
}

func TestDockerDriverRejectsHostNetwork(t *testing.T) {
	d := NewDockerDriver(DockerOptions{})
	_, err := d.Launch(context.Background(), proto.SandboxSpec{
		Image:       "node:20-slim",
		NetworkMode: "host",
	})
	if err == nil || !strings.Contains(err.Error(), "NetworkMode") {
		t.Errorf("want NetworkMode rejection, got %v", err)
	}
}

// fakeHandle implements Handle for tests that exercise the runner glue
// without contacting Docker. Kept here (next to the interface) so the
// runner package can reuse it via go test -tags ... later if needed.
type fakeHandle struct {
	cgroupID    uint64
	containerID string
	waitCh      chan WaitResult
	stopped     bool
}

func (f *fakeHandle) CgroupID() uint64        { return f.cgroupID }
func (f *fakeHandle) ContainerID() string     { return f.containerID }
func (f *fakeHandle) ImageDigest() string     { return "fake@sha256:0" }
func (f *fakeHandle) Wait() <-chan WaitResult { return f.waitCh }
func (f *fakeHandle) Stop(_ context.Context) error {
	f.stopped = true
	return nil
}

func TestFakeHandleStopFlow(t *testing.T) {
	h := &fakeHandle{
		cgroupID:    42,
		containerID: "deadbeef1234",
		waitCh:      make(chan WaitResult, 1),
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		h.waitCh <- WaitResult{ExitCode: 0}
	}()
	select {
	case res := <-h.Wait():
		if res.ExitCode != 0 {
			t.Errorf("ExitCode: got %d", res.ExitCode)
		}
	case <-time.After(time.Second):
		t.Fatal("Wait() never fired")
	}
	if err := h.Stop(context.Background()); err != nil {
		t.Errorf("Stop: %v", err)
	}
	if !h.stopped {
		t.Errorf("Stop did not mark stopped")
	}
}

func toFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	default:
		return -1
	}
}
