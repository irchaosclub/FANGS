// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

// EventStreamer batches events for a single run and POSTs them to
// /v1/runs/<run_id>/events as NDJSON. One streamer per run; create with
// NewEventStreamer, write via Send, finish with Close.
//
// Batching: flush every FlushInterval or when Buffer fills, whichever
// first. Drops are surfaced by orchestrator-side missing-seq detection.
type EventStreamer struct {
	baseURL  string
	runID    [16]byte
	runIDHex string

	client *http.Client
	logger interface {
		Info(string, ...any)
		Warn(string, ...any)
	}

	flushInterval time.Duration
	maxBatch      int

	in    chan proto.EventEnvelope
	done  chan struct{}
	seq   atomic.Uint64
	stats StreamStats
}

// StreamStats reports cumulative streamer activity.
type StreamStats struct {
	BatchesSent     uint64
	EventsSent      uint64
	BatchSendErrors uint64
}

// NewEventStreamer constructs and starts a streamer. The caller's
// context bounds the streamer's lifetime; canceling it triggers a final
// flush + Close. Pass transport=nil for plain HTTP; pass cli.Transport()
// when the orchestrator URL is https://.
func NewEventStreamer(ctx context.Context, baseURL string, runID [16]byte, logger interface {
	Info(string, ...any)
	Warn(string, ...any)
}, transport *http.Transport) *EventStreamer {
	// Build http.Client carefully — typed-nil *http.Transport stored in
	// the RoundTripper interface field crashes net/http on Do().
	hc := &http.Client{Timeout: 10 * time.Second}
	if transport != nil {
		hc.Transport = transport
	}
	s := &EventStreamer{
		baseURL:       baseURL,
		runID:         runID,
		runIDHex:      fmt.Sprintf("%x", runID),
		client:        hc,
		logger:        logger,
		flushInterval: 250 * time.Millisecond,
		maxBatch:      64,
		in:            make(chan proto.EventEnvelope, 1024),
		done:          make(chan struct{}),
	}
	go s.loop(ctx)
	return s
}

// Send queues an event for the next batch. Non-blocking: if the in-queue
// is full (1024 events backlog), the event is dropped with a warning.
func (s *EventStreamer) Send(envelope proto.EventEnvelope) {
	select {
	case s.in <- envelope:
	default:
		s.logger.Warn("event streamer queue full; dropping", "run_id", s.runIDHex)
	}
}

// Stats returns a snapshot of streamer activity since start.
func (s *EventStreamer) Stats() StreamStats { return s.stats }

// Close signals the streamer to flush any remaining batch and stop.
// Blocks until the loop exits.
func (s *EventStreamer) Close() {
	close(s.in)
	<-s.done
}

func (s *EventStreamer) loop(ctx context.Context) {
	defer close(s.done)
	tick := time.NewTicker(s.flushInterval)
	defer tick.Stop()
	pending := make([]proto.EventEnvelope, 0, s.maxBatch)

	flush := func() {
		if len(pending) == 0 {
			return
		}
		batch := proto.EventBatch{
			RunID:  s.runID,
			Seq:    s.seq.Add(1),
			Events: pending,
		}
		if err := s.post(ctx, batch); err != nil {
			s.stats.BatchSendErrors++
			s.logger.Warn("event batch POST failed", "err", err, "seq", batch.Seq, "events", len(batch.Events))
		} else {
			s.stats.BatchesSent++
			s.stats.EventsSent += uint64(len(batch.Events))
		}
		pending = pending[:0]
	}

	for {
		select {
		case ev, ok := <-s.in:
			if !ok {
				flush()
				return
			}
			pending = append(pending, ev)
			if len(pending) >= s.maxBatch {
				flush()
			}
		case <-tick.C:
			flush()
		case <-ctx.Done():
			flush()
			return
		}
	}
}

func (s *EventStreamer) post(ctx context.Context, batch proto.EventBatch) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal batch: %w", err)
	}
	url := fmt.Sprintf("%s/v1/runs/%s/events", s.baseURL, s.runIDHex)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("orchestrator returned %d: %s", resp.StatusCode, string(b))
	}
	return nil
}
