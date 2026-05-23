// SPDX-License-Identifier: Apache-2.0
//
// Integration tests that exercise the DockerDriver against a real
// daemon. They self-skip when /var/run/docker.sock is not reachable or
// the test runner is not allowed to pull/run images.
//
// Run explicitly with:  go test ./internal/runner/sandbox -run Integration

package sandbox

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

func dockerReachable(t *testing.T) bool {
	t.Helper()
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		return false
	}
	c, err := net.DialTimeout("unix", "/var/run/docker.sock", 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func TestIntegrationLaunchBusybox(t *testing.T) {
	if !dockerReachable(t) {
		t.Skip("docker socket not reachable; skipping")
	}
	if os.Getenv("FANGS_SKIP_DOCKER_INTEGRATION") == "1" {
		t.Skip("FANGS_SKIP_DOCKER_INTEGRATION set; skipping")
	}

	d := NewDockerDriver(DockerOptions{})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	spec := proto.SandboxSpec{
		Image:       "busybox:1.36",
		Command:     []string{"sh", "-c", "sleep 5"},
		NetworkMode: "none",
		PullPolicy:  "missing",
		User:        "0:0", // busybox doesn't have user 1000; override default
	}
	h, err := d.Launch(ctx, spec)
	if err != nil {
		if errors.Is(err, ErrCgroupV2Required) {
			t.Skipf("host Docker daemon is not on cgroup v2 systemd driver; skipping: %v", err)
		}
		t.Fatalf("Launch: %v", err)
	}
	defer func() {
		stopCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = h.Stop(stopCtx)
	}()

	if h.CgroupID() == 0 {
		t.Errorf("expected non-zero cgroup id")
	}
	if h.ContainerID() == "" {
		t.Errorf("expected non-empty container id")
	}

	t.Logf("launched %s (cgroup_id=%d, digest=%s)", h.ContainerID()[:12], h.CgroupID(), h.ImageDigest())

	select {
	case res := <-h.Wait():
		if res.Err != nil {
			t.Errorf("Wait returned error: %v", res.Err)
		}
		if res.ExitCode != 0 {
			t.Logf("container exit code %d (acceptable for this test)", res.ExitCode)
		}
	case <-time.After(15 * time.Second):
		t.Errorf("container did not exit within 15s")
	}
}
