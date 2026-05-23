// SPDX-License-Identifier: Apache-2.0
package sandbox

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ErrCgroupV2Required is returned when the host doesn't expose a
// cgroup v2 hierarchy that Docker actually populated. This usually
// means the Docker daemon is on the legacy cgroupfs v1 driver — FANGS
// requires cgroup v2 + systemd driver for per-container multiplexing.
var ErrCgroupV2Required = errors.New("sandbox: cgroup v2 with systemd driver required (see https://github.com/irchaosclub/FANGS/wiki/Installation)")

// cgroupV2Root returns the absolute path where the v2 unified
// hierarchy is mounted. Most modern hosts have it at /sys/fs/cgroup,
// but hybrid systems mount it at /sys/fs/cgroup/unified. The result is
// cached on first lookup.
func cgroupV2Root() (string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", fmt.Errorf("open mountinfo: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// mountinfo lines have ' - ' separating the optional fields
		// from the filesystem type / source. Look for "cgroup2" type.
		dash := strings.Index(line, " - ")
		if dash < 0 {
			continue
		}
		head, tail := line[:dash], line[dash+3:]
		if !strings.HasPrefix(tail, "cgroup2 ") {
			continue
		}
		fields := strings.Fields(head)
		// Field index 4 (0-based) is the mount point.
		if len(fields) >= 5 {
			return fields[4], nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", ErrCgroupV2Required
}

// cgroupPathForPID returns the unified-hierarchy cgroup path for the
// given pid by parsing /proc/<pid>/cgroup and joining the result to
// the actual v2 mount point.
func cgroupPathForPID(pid int) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", fmt.Errorf("open /proc/%d/cgroup: %w", pid, err)
	}
	defer f.Close()
	rel, err := parseCgroupReader(bufio.NewScanner(f))
	if err != nil {
		return "", err
	}
	root, err := cgroupV2Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, rel), nil
}

// parseCgroupReader returns the cgroup PATH (relative to the unified
// hierarchy root, leading slash included). Caller joins it to the
// detected v2 mount point.
func parseCgroupReader(sc *bufio.Scanner) (string, error) {
	for sc.Scan() {
		line := sc.Text()
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			return strings.TrimSpace(parts[2]), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", ErrCgroupV2Required
}

// cgroupIDForPath returns the kernel cgroup id (inode of the directory)
// for an absolute cgroup path on the v2 hierarchy. Matches what the
// sensor's CGMAP key uses. Returns ErrCgroupV2Required when the path
// does not exist — Docker on the legacy v1 driver advertises a v2 path
// in /proc/<pid>/cgroup but never creates the corresponding directory.
func cgroupIDForPath(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("%w (resolved path %q does not exist)", ErrCgroupV2Required, path)
		}
		return 0, fmt.Errorf("stat %q: %w", path, err)
	}
	return st.Ino, nil
}

// CreateParentCgroup creates a FANGS-managed parent cgroup that the
// sandbox container will be nested under. The returned (relativePath,
// absolutePath, cgroupID) lets the caller:
//   - Register the cgroupID in CGMAP BEFORE the container starts (so the
//     sensor catches the container's very first syscalls via ancestor walk).
//   - Pass relativePath to Docker as HostConfig.CgroupParent.
//   - rmdir absolutePath in cleanup.
//
// Path scheme: /fangs/<run-id-hex>/  under the v2 mount root. Idempotent
// on the parent /fangs/ — created once.
func CreateParentCgroup(runIDHex string) (relPath, absPath string, cgroupID uint64, err error) {
	root, err := cgroupV2Root()
	if err != nil {
		return "", "", 0, err
	}
	// Ensure /fangs exists.
	fangsRoot := filepath.Join(root, "fangs")
	if err := os.MkdirAll(fangsRoot, 0o755); err != nil {
		return "", "", 0, fmt.Errorf("mkdir %s: %w", fangsRoot, err)
	}
	// Per-run subdir.
	relPath = "/fangs/" + runIDHex
	absPath = filepath.Join(root, "fangs", runIDHex)
	if err := os.Mkdir(absPath, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return "", "", 0, fmt.Errorf("mkdir %s: %w", absPath, err)
	}
	cgroupID, err = cgroupIDForPath(absPath)
	if err != nil {
		_ = os.Remove(absPath)
		return "", "", 0, err
	}
	return relPath, absPath, cgroupID, nil
}

// RemoveParentCgroup rmdir's the absPath returned from CreateParentCgroup.
// Best-effort — if Docker hasn't fully torn down child cgroups yet, the
// rmdir fails with EBUSY and we return that error so the caller can retry.
func RemoveParentCgroup(absPath string) error {
	return os.Remove(absPath)
}
