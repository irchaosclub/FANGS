// SPDX-License-Identifier: Apache-2.0
//
// Package core hosts the orchestrator's control-plane logic that's not
// specifically HTTP-shaped: the job queue, runner state tracking, and
// (later) the scan lifecycle state machine.
package core

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

// Dispatcher holds pending jobs and hands them out to runners that
// long-poll for work. In-memory only for now; persistence lands when
// we add the storage layer.
//
// Concurrency model: a single sync.Mutex guards the per-runner queue
// map; long-pollers wait on a per-runner condition variable signaled
// when QueueJob is called.
type Dispatcher struct {
	mu      sync.Mutex
	queues  map[string][]proto.Job   // runner_id -> pending jobs (FIFO)
	signals map[string]chan struct{} // runner_id -> buffered(1) wake channel
}

// New constructs an empty Dispatcher.
func New() *Dispatcher {
	return &Dispatcher{
		queues:  make(map[string][]proto.Job),
		signals: make(map[string]chan struct{}),
	}
}

// QueueJob appends a job to the named runner's queue and wakes any long-
// pollers waiting on that runner.
func (d *Dispatcher) QueueJob(runnerID string, job proto.Job) {
	d.mu.Lock()
	d.queues[runnerID] = append(d.queues[runnerID], job)
	sig := d.getSignal(runnerID)
	d.mu.Unlock()
	// Non-blocking send: the channel is buffered(1), so any wake already
	// pending is sufficient.
	select {
	case sig <- struct{}{}:
	default:
	}
}

// PollJob long-polls for the next job for the named runner. Returns
// (job, true) when one is available, (zero, false) when ctx expires
// (either due to timeout or cancellation).
//
// Callers pass a context with a server-chosen timeout (typically the
// runner's job_poll_interval) so the long-poll bounds itself.
func (d *Dispatcher) PollJob(ctx context.Context, runnerID string) (proto.Job, bool) {
	for {
		d.mu.Lock()
		if jobs := d.queues[runnerID]; len(jobs) > 0 {
			next := jobs[0]
			d.queues[runnerID] = jobs[1:]
			d.mu.Unlock()
			return next, true
		}
		sig := d.getSignal(runnerID)
		d.mu.Unlock()

		select {
		case <-sig:
			// Wake; re-check the queue at the top of the loop.
		case <-ctx.Done():
			return proto.Job{}, false
		}
	}
}

// QueueDepth returns the number of pending jobs for a runner.
func (d *Dispatcher) QueueDepth(runnerID string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.queues[runnerID])
}

// getSignal returns the wake channel for a runner, creating it lazily.
// Caller must hold d.mu.
func (d *Dispatcher) getSignal(runnerID string) chan struct{} {
	sig, ok := d.signals[runnerID]
	if !ok {
		sig = make(chan struct{}, 1)
		d.signals[runnerID] = sig
	}
	return sig
}

// ErrJobNotForRunner is returned by checks that catch misrouted jobs.
// Currently unused; kept for the day we add a "this runner can't handle
// this job kind" rejection path.
var ErrJobNotForRunner = errors.New("job not eligible for this runner")

// SyntheticRunID returns a 16-byte run id derived from the current
// nanosecond timestamp. Useful for test scans queued via POST /v1/scans
// without a real upstream id source. Production scan paths use ULIDs.
func SyntheticRunID() [16]byte {
	var out [16]byte
	t := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		out[i] = byte(t >> (56 - 8*i))
	}
	return out
}
