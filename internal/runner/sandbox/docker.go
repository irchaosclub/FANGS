// SPDX-License-Identifier: Apache-2.0
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

// DockerDriver speaks the Docker Engine API over the host UNIX socket
// using stdlib net/http. No third-party SDK is pulled in — this keeps
// the runner binary slim and avoids the Docker client's CVE surface.
type DockerDriver struct {
	socketPath string
	apiVersion string
	http       *http.Client
	logger     *slog.Logger
}

// DockerOptions configures a DockerDriver.
type DockerOptions struct {
	// SocketPath defaults to /var/run/docker.sock.
	SocketPath string
	// APIVersion defaults to v1.41 (broadly compatible with Docker 20.10+).
	APIVersion string
	Logger     *slog.Logger
}

// NewDockerDriver constructs a DockerDriver. It does not contact the
// daemon — that happens on first Launch.
func NewDockerDriver(opts DockerOptions) *DockerDriver {
	if opts.SocketPath == "" {
		opts.SocketPath = "/var/run/docker.sock"
	}
	if opts.APIVersion == "" {
		opts.APIVersion = "v1.41"
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "unix", opts.SocketPath)
		},
		// Disable pooling: a single-shot RPC per call is plenty.
		DisableKeepAlives: true,
	}
	return &DockerDriver{
		socketPath: opts.SocketPath,
		apiVersion: opts.APIVersion,
		http:       &http.Client{Transport: transport},
		logger:     logger,
	}
}

// Launch implements Driver.
func (d *DockerDriver) Launch(ctx context.Context, spec proto.SandboxSpec) (Handle, error) {
	if spec.Image == "" {
		return nil, ErrImageRequired
	}
	if strings.EqualFold(spec.NetworkMode, "host") {
		return nil, fmt.Errorf("sandbox: NetworkMode=%q forbidden", spec.NetworkMode)
	}
	filled := FilledSpec(spec)

	if err := d.pullIfNeeded(ctx, filled.Image, filled.PullPolicy); err != nil {
		return nil, fmt.Errorf("pull image: %w", err)
	}

	digest, err := d.resolveDigest(ctx, filled.Image)
	if err != nil {
		// Soft-fail: log and proceed with the tag. Digest pinning is a
		// defense-in-depth feature, not a launch blocker on registries
		// that don't expose digests (private mirrors, local tags).
		d.logger.Warn("could not resolve image digest; proceeding with tag", "image", filled.Image, "err", err)
		digest = ""
	}

	createBody := buildCreatePayload(filled, digest)
	containerID, err := d.createContainer(ctx, createBody)
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}

	if err := d.startContainer(ctx, containerID); err != nil {
		_ = d.removeContainer(context.Background(), containerID, true)
		return nil, fmt.Errorf("start container: %w", err)
	}

	pid, err := d.waitForRunning(ctx, containerID, 10*time.Second)
	if err != nil {
		_ = d.removeContainer(context.Background(), containerID, true)
		return nil, fmt.Errorf("resolve container PID: %w", err)
	}

	// Poll /proc/<pid>/cgroup until Docker has moved the process into
	// its final cgroup. With fast (5ms) waitForRunning polling we can
	// catch the PID before placement; the cgroup path then shows "/"
	// or a transitional value whose inode no longer matches the actual
	// container cgroup once setup finishes. Wait until the path is
	// non-root AND the dir exists.
	cgroupPath, cgroupID, err := d.stableCgroup(ctx, pid, 5*time.Second)
	if err != nil {
		_ = d.removeContainer(context.Background(), containerID, true)
		return nil, fmt.Errorf("resolve cgroup for pid %d: %w", pid, err)
	}

	h := &dockerHandle{
		driver:      d,
		containerID: containerID,
		cgroupID:    cgroupID,
		cgroupPath:  cgroupPath,
		imageDigest: digest,
		spec:        filled,
		waitCh:      make(chan WaitResult, 1),
	}
	go h.runWait()

	d.logger.Info("sandbox launched",
		"container_id", containerID[:12],
		"image", filled.Image,
		"digest", digest,
		"cgroup_id", cgroupID,
		"network_mode", filled.NetworkMode,
		"user", filled.User,
		"pids_limit", filled.PidsLimit,
	)
	return h, nil
}

// dockerHandle implements Handle for a running Docker container.
type dockerHandle struct {
	driver      *DockerDriver
	containerID string
	cgroupID    uint64
	cgroupPath  string
	imageDigest string
	spec        proto.SandboxSpec
	waitCh      chan WaitResult
}

func (h *dockerHandle) CgroupID() uint64        { return h.cgroupID }
func (h *dockerHandle) ContainerID() string     { return h.containerID }
func (h *dockerHandle) ImageDigest() string     { return h.imageDigest }
func (h *dockerHandle) Wait() <-chan WaitResult { return h.waitCh }

// runWait blocks on the Docker /wait endpoint until the container exits,
// then emits a WaitResult.
func (h *dockerHandle) runWait() {
	res, err := h.driver.waitContainer(context.Background(), h.containerID)
	if err != nil {
		h.waitCh <- WaitResult{Err: err}
		return
	}
	h.waitCh <- res
}

// Stop tries graceful SIGTERM, then forces removal. Safe to call
// multiple times.
func (h *dockerHandle) Stop(ctx context.Context) error {
	if err := h.driver.stopContainer(ctx, h.containerID, DefaultStopTimeout); err != nil {
		// Best-effort: continue to force-remove even if stop fails.
		h.driver.logger.Warn("docker stop failed; forcing remove", "err", err, "container_id", h.containerID[:12])
	}
	return h.driver.removeContainer(ctx, h.containerID, true)
}

// --- HTTP helpers ---

func (d *DockerDriver) url(path string) string {
	return "http://docker/" + d.apiVersion + path
}

func (d *DockerDriver) do(ctx context.Context, method, path string, body io.Reader, accepted ...int) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, d.url(path), body)
	if err != nil {
		return nil, fmt.Errorf("build %s %s: %w", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.http.Do(req)
	if err != nil {
		// Wrap the very common socket-perm error with a more useful message.
		if strings.Contains(err.Error(), "connect: permission denied") || strings.Contains(err.Error(), "connect: no such file") {
			return nil, fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
		}
		return nil, err
	}
	if len(accepted) == 0 {
		accepted = []int{http.StatusOK}
	}
	for _, want := range accepted {
		if resp.StatusCode == want {
			return resp, nil
		}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return nil, fmt.Errorf("docker API %s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
}

func (d *DockerDriver) pullIfNeeded(ctx context.Context, image, policy string) error {
	switch policy {
	case "never":
		return nil
	case "missing":
		if d.imageExists(ctx, image) {
			return nil
		}
	case "always":
		// fallthrough to pull
	default:
		return fmt.Errorf("unknown PullPolicy %q", policy)
	}
	fromImage, tag := splitImageTag(image)
	q := url.Values{"fromImage": {fromImage}, "tag": {tag}}
	resp, err := d.do(ctx, http.MethodPost, "/images/create?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// /images/create streams JSON progress lines until the pull completes.
	// We don't need the progress, but we MUST drain the body or the
	// daemon may stall.
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (d *DockerDriver) imageExists(ctx context.Context, image string) bool {
	resp, err := d.do(ctx, http.MethodGet, "/images/"+url.PathEscape(image)+"/json", nil)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func (d *DockerDriver) resolveDigest(ctx context.Context, image string) (string, error) {
	resp, err := d.do(ctx, http.MethodGet, "/images/"+url.PathEscape(image)+"/json", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var info struct {
		ID          string   `json:"Id"`
		RepoDigests []string `json:"RepoDigests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", err
	}
	if len(info.RepoDigests) > 0 {
		// Pick the digest that matches our repo name when there are many.
		repo, _ := splitImageTag(image)
		for _, rd := range info.RepoDigests {
			if strings.HasPrefix(rd, repo+"@") {
				return rd, nil
			}
		}
		return info.RepoDigests[0], nil
	}
	return info.ID, nil
}

func (d *DockerDriver) createContainer(ctx context.Context, body []byte) (string, error) {
	resp, err := d.do(ctx, http.MethodPost, "/containers/create", bytes.NewReader(body), http.StatusCreated)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		ID       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	for _, w := range out.Warnings {
		d.logger.Warn("docker create warning", "warning", w)
	}
	return out.ID, nil
}

func (d *DockerDriver) startContainer(ctx context.Context, id string) error {
	resp, err := d.do(ctx, http.MethodPost, "/containers/"+id+"/start", nil, http.StatusNoContent, http.StatusNotModified)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// stableCgroup resolves pid -> (cgroup path, cgroup id) only after the
// process has been moved out of the root cgroup AND the resolved
// directory exists on disk. This closes a race between Docker's
// container-start syscalls and our PID polling: with 5ms polling we
// can read /proc/<pid>/cgroup BEFORE Docker has placed the process in
// its final scope, then write the wrong inode into CGMAP and miss
// every event from the container.
func (d *DockerDriver) stableCgroup(ctx context.Context, pid int, timeout time.Duration) (string, uint64, error) {
	deadline := time.Now().Add(timeout)
	for {
		path, err := cgroupPathForPID(pid)
		if err == nil && path != "" && !strings.HasSuffix(path, "/sys/fs/cgroup") {
			// Cgroup path looks final. Confirm the dir exists (LPM trie
			// stat will fail if not).
			id, err := cgroupIDForPath(path)
			if err == nil {
				return path, id, nil
			}
		}
		if time.Now().After(deadline) {
			return "", 0, fmt.Errorf("cgroup placement did not stabilize for pid %d within %s", pid, timeout)
		}
		select {
		case <-ctx.Done():
			return "", 0, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (d *DockerDriver) waitForRunning(ctx context.Context, id string, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for {
		pid, status, err := d.inspectPID(ctx, id)
		if err != nil {
			return 0, err
		}
		if pid > 0 && status == "running" {
			return pid, nil
		}
		if status == "exited" || status == "dead" {
			return 0, fmt.Errorf("container entered %s before becoming running", status)
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("%w (status=%s)", ErrLaunchTimeout, status)
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (d *DockerDriver) inspectPID(ctx context.Context, id string) (int, string, error) {
	resp, err := d.do(ctx, http.MethodGet, "/containers/"+id+"/json", nil)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	var info struct {
		State struct {
			Pid    int    `json:"Pid"`
			Status string `json:"Status"`
		} `json:"State"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return 0, "", err
	}
	return info.State.Pid, info.State.Status, nil
}

func (d *DockerDriver) waitContainer(ctx context.Context, id string) (WaitResult, error) {
	resp, err := d.do(ctx, http.MethodPost, "/containers/"+id+"/wait", nil)
	if err != nil {
		return WaitResult{}, err
	}
	defer resp.Body.Close()
	var w struct {
		StatusCode int `json:"StatusCode"`
		Error      *struct {
			Message string `json:"Message"`
		} `json:"Error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&w); err != nil {
		return WaitResult{}, err
	}
	res := WaitResult{ExitCode: w.StatusCode}
	if w.Error != nil {
		res.Err = fmt.Errorf("container error: %s", w.Error.Message)
	}
	// OOM detection requires a second inspect; keep it cheap.
	if pid, _, err := d.inspectPID(ctx, id); err == nil && pid == 0 {
		// nothing — keep room for future OOMKilled detection
	}
	return res, nil
}

func (d *DockerDriver) stopContainer(ctx context.Context, id string, timeout time.Duration) error {
	q := url.Values{"t": {fmt.Sprintf("%d", int(timeout.Seconds()))}}
	resp, err := d.do(ctx, http.MethodPost, "/containers/"+id+"/stop?"+q.Encode(), nil, http.StatusNoContent, http.StatusNotModified)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (d *DockerDriver) removeContainer(ctx context.Context, id string, force bool) error {
	q := url.Values{}
	if force {
		q.Set("force", "true")
	}
	resp, err := d.do(ctx, http.MethodDelete, "/containers/"+id+"?"+q.Encode(), nil, http.StatusNoContent, http.StatusNotFound)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// --- payload builders ---

// buildCreatePayload constructs the JSON body for POST /containers/create.
// Defaults already applied via FilledSpec. digestRef is used as the
// Image field if non-empty (pin to immutable digest); otherwise the
// human-readable tag is used.
func buildCreatePayload(spec proto.SandboxSpec, digestRef string) []byte {
	imageRef := spec.Image
	if digestRef != "" {
		imageRef = digestRef
	}
	body := map[string]any{
		"Image":      imageRef,
		"User":       spec.User,
		"WorkingDir": spec.WorkingDir,
		"Env":        envSlice(spec.Env),
		"Cmd":        spec.Command,
		"Labels": map[string]string{
			"io.fangs.role": "sandbox",
		},
		"HostConfig": map[string]any{
			"CapDrop":      []string{"ALL"},
			"SecurityOpt":  []string{"no-new-privileges:true"},
			"NetworkMode":  spec.NetworkMode,
			"PidMode":      "",
			"IpcMode":      "",
			"UTSMode":      "",
			"Memory":       spec.MemoryBytes,
			"NanoCpus":     spec.NanoCPUs,
			"PidsLimit":    spec.PidsLimit,
			"CgroupParent": spec.CgroupParent,
			"Ulimits": []map[string]any{
				{"Name": "nofile", "Soft": 1024, "Hard": 2048},
				{"Name": "nproc", "Soft": 256, "Hard": 256},
				{"Name": "fsize", "Soft": 268435456, "Hard": 268435456},
			},
			"Tmpfs": map[string]string{
				"/tmp": "rw,nosuid,nodev,noexec,size=256m",
				"/run": "rw,nosuid,nodev,size=16m",
			},
			"LogConfig": map[string]any{
				"Type":   "json-file",
				"Config": map[string]string{"max-size": "10m", "max-file": "3"},
			},
			"RestartPolicy": map[string]any{"Name": "no"},
		},
	}
	b, _ := json.Marshal(body)
	return b
}

func envSlice(in map[string]string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for k, v := range in {
		out = append(out, k+"="+v)
	}
	return out
}

func splitImageTag(image string) (string, string) {
	// Strip digest first — `repo@sha256:...` overrides any tag.
	if at := strings.LastIndex(image, "@"); at >= 0 {
		return image[:at], ""
	}
	// Tag is the last ":" segment AFTER the last "/". A colon in a
	// host:port prefix (e.g. "registry.local:5000/img") is not a tag.
	slash := strings.LastIndex(image, "/")
	colon := strings.LastIndex(image, ":")
	if colon > slash {
		return image[:colon], image[colon+1:]
	}
	return image, "latest"
}
