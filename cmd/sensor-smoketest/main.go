// SPDX-License-Identifier: Apache-2.0
//
// sensor-smoketest is a thin CLI wrapper around the internal/runner/sensor
// package. It parses flags, opens a sensor for one cgroup with one or more
// watched-path prefixes, and prints each captured event as a JSON line on
// stdout until interrupted. The package itself is what the production
// fangs-runner binary will use.
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/irchaosclub/FANGS/internal/runner/sensor"
	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

// watchSpec is a `-watch` flag value: either "PREFIX" (keep) or
// "PREFIX@cred" (keep + cred-tagged). Repeatable.
type watchSpec struct {
	Prefix     string
	CredTagged bool
}

type watchList []watchSpec

func (w *watchList) String() string {
	out := make([]string, 0, len(*w))
	for _, s := range *w {
		if s.CredTagged {
			out = append(out, s.Prefix+"@cred")
		} else {
			out = append(out, s.Prefix)
		}
	}
	return strings.Join(out, ",")
}

func (w *watchList) Set(v string) error {
	credTagged := false
	if suffix := "@cred"; strings.HasSuffix(v, suffix) {
		v = strings.TrimSuffix(v, suffix)
		credTagged = true
	}
	if v == "" {
		return errors.New("empty path prefix")
	}
	if !strings.HasPrefix(v, "/") {
		return fmt.Errorf("watch prefix must be absolute (start with /): %q", v)
	}
	if len(v) > proto.PathLen {
		return fmt.Errorf("watch prefix exceeds %d bytes: %q", proto.PathLen, v)
	}
	*w = append(*w, watchSpec{Prefix: v, CredTagged: credTagged})
	return nil
}

func main() {
	var (
		cgroupPath = flag.String("cgroup-path", "", "absolute path to the cgroup to watch (e.g. /sys/fs/cgroup/system.slice/docker-<id>.scope). Required.")
		runIDHex   = flag.String("run-id", "", "32-hex run id (16 bytes). If empty, a synthetic one is generated from the current time.")
		jsonOut    = flag.Bool("json", true, "emit events as JSON lines on stdout.")
		watches    watchList
	)
	flag.Var(&watches, "watch", "watched-path prefix; repeat for more. Suffix '@cred' tags matching events as cred_access. Required (at least one).")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *cgroupPath == "" {
		logger.Error("missing -cgroup-path")
		flag.Usage()
		os.Exit(2)
	}
	if len(watches) == 0 {
		logger.Error("missing -watch (need at least one watched path prefix)")
		flag.Usage()
		os.Exit(2)
	}

	if err := run(logger, *cgroupPath, *runIDHex, *jsonOut, watches); err != nil {
		logger.Error("sensor failed", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, cgroupPath, runIDHex string, jsonOut bool, watches watchList) error {
	cgroupID, err := cgroupIDFromPath(cgroupPath)
	if err != nil {
		return fmt.Errorf("resolve cgroup id from %q: %w", cgroupPath, err)
	}
	logger.Info("resolved cgroup", "path", cgroupPath, "id", cgroupID)

	runID, err := parseOrGenerateRunID(runIDHex)
	if err != nil {
		return fmt.Errorf("run id: %w", err)
	}
	logger.Info("run id", "hex", hex.EncodeToString(runID[:]))

	watched := make([]sensor.WatchedPath, 0, len(watches))
	for _, w := range watches {
		watched = append(watched, sensor.WatchedPath{Prefix: w.Prefix, CredTagged: w.CredTagged})
	}

	s, err := sensor.New(sensor.Options{
		Logger:        logger,
		EnsureTracefs: true,
		DedupWindow:   5 * time.Second,
	})
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.AddCgroup(sensor.AddCgroupOptions{
		CgroupID:     cgroupID,
		RunID:        runID,
		WatchedPaths: watched,
	}); err != nil {
		return fmt.Errorf("AddCgroup: %w", err)
	}
	defer s.RemoveCgroup(cgroupID)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger.Info("reading events — Ctrl-C to stop")
	enc := json.NewEncoder(os.Stdout)
	startWall := time.Now()
	var eventsEmitted int64

	for ev := range s.Events(ctx) {
		eventsEmitted++
		if !jsonOut {
			continue
		}
		if err := enc.Encode(eventToJSON(ev, startWall)); err != nil {
			return fmt.Errorf("json encode: %w", err)
		}
	}

	drops, derr := s.Drops()
	args := []any{
		"events_emitted", eventsEmitted,
		"elapsed", time.Since(startWall).String(),
	}
	if derr != nil {
		args = append(args, "drops_read_err", derr)
	} else {
		args = append(args, "events_dropped", drops)
	}
	logger.Info("sensor closed, exiting", args...)
	return nil
}

func cgroupIDFromPath(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat: %w", err)
	}
	return st.Ino, nil
}

func parseOrGenerateRunID(hexStr string) ([proto.RunIDLen]byte, error) {
	var out [proto.RunIDLen]byte
	if hexStr == "" {
		binary.BigEndian.PutUint64(out[:8], uint64(time.Now().UnixNano()))
		return out, nil
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return out, fmt.Errorf("parse hex: %w", err)
	}
	if len(b) != proto.RunIDLen {
		return out, fmt.Errorf("run id must be exactly %d bytes (%d hex chars); got %d bytes", proto.RunIDLen, proto.RunIDLen*2, len(b))
	}
	copy(out[:], b)
	return out, nil
}
