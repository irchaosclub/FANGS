// SPDX-License-Identifier: Apache-2.0
//
// Package sensor implements the FANGS eBPF event capture: it loads CO-RE BPF
// programs, attaches probes for file/exec/network/DNS/TLS events from a target
// cgroup, and exposes the resulting stream as a typed Go channel.
//
// Usage:
//
//	// At runner startup — attach probes once, hold for the runner's lifetime.
//	s, err := sensor.New(sensor.Options{
//	    Logger:        slog.Default(),
//	    EnsureTracefs: true,
//	    DedupWindow:   5 * time.Second,
//	})
//	if err != nil { ... }
//	defer s.Close()
//
//	// Per-scan: register the target cgroup, run the sandbox, deregister.
//	if err := s.AddCgroup(sensor.AddCgroupOptions{
//	    CgroupID:     cgroupID,
//	    RunID:        runID,
//	    WatchedPaths: []sensor.WatchedPath{{Prefix: "/etc/"}},
//	}); err != nil { ... }
//	defer s.RemoveCgroup(cgroupID)
//
//	for ev := range s.Events(ctx) {
//	    switch e := ev.(type) {
//	    case *sensor.FileAccessEvent: ...
//	    case *sensor.ExecEvent:       ...
//	    case *sensor.NetConnectEvent: ...
//	    case *sensor.DNSQueryEvent:   ...
//	    case *sensor.TLSSniEvent:     ...
//	    }
//	}
//
// Probes are global; only processes whose cgroup is in CGMAP produce
// events. This pre-attach-then-AddCgroup pattern closes the
// container-start vs sensor-attach race window — events from the very
// first syscall in the sandbox container are observable.
package sensor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

// Sensor owns the eBPF programs, maps, and ringbuf reader. Construct
// with New, register cgroups via AddCgroup, consume events via Events,
// release with Close.
//
// A single Sensor supports one runner. Per-job cgroup registration is
// dynamic — call AddCgroup before docker start, RemoveCgroup after
// teardown.
type Sensor struct {
	logger *slog.Logger

	objs   sensorObjects
	links  []link.Link
	reader *ringbuf.Reader
	drops  *ebpf.Map

	dedup     *tlsDedup
	connDedup *connectDedup

	// cgroupsMu protects registered. Per-job AddCgroup/RemoveCgroup
	// serialize through this lock so path_filter mutations don't race.
	cgroupsMu  sync.Mutex
	registered map[uint64][]WatchedPath // cgroup_id -> active watched paths

	closeOnce sync.Once
	closeErr  error
}

// New constructs a Sensor: removes MEMLOCK, optionally mounts tracefs,
// loads the embedded BPF object, attaches all tracepoints + the libssl
// uprobe (best-effort), opens the ringbuf reader. CGMAP and path_filter
// start empty — call AddCgroup before a job to start observing it.
func New(opts Options) (*Sensor, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit.RemoveMemlock: %w", err)
	}
	if opts.EnsureTracefs {
		if err := ensureTracefs(logger); err != nil {
			return nil, fmt.Errorf("tracefs: %w", err)
		}
	}

	s := &Sensor{
		logger:     logger,
		registered: make(map[uint64][]WatchedPath),
	}
	if opts.DedupWindow > 0 {
		s.dedup = newTLSDedup(opts.DedupWindow)
	}
	// Connect dedup collapses the (tracepoint, kprobe) pair fired for one
	// syscall-path TCP connect. The BPF programs stamp Source: syscall
	// events from sys_enter_connect get NetSourceSyscall, kprobe events
	// from tcp_v{4,6}_connect get NetSourceKprobe. Dedup is asymmetric —
	// kprobe events get dropped iff a same-key syscall event arrived
	// within the window; syscall events are always emitted. This preserves
	// io_uring connects (kprobe with no syscall pair) and never collapses
	// two legitimate app-level connects to the same destination.
	s.connDedup = newConnectDedup(100 * time.Millisecond)

	if err := loadSensorObjects(&s.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected program:\n%+v", ve)
		}
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}
	s.drops = s.objs.DropsCounter

	tps := []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"syscalls", "sys_enter_openat", s.objs.HandleOpenat},
		{"syscalls", "sys_enter_execve", s.objs.HandleExecve},
		{"syscalls", "sys_enter_connect", s.objs.HandleConnect},
		{"syscalls", "sys_enter_sendto", s.objs.HandleSendto},
		{"syscalls", "sys_enter_sendmmsg", s.objs.HandleSendmmsg},
		{"syscalls", "sys_enter_sendmsg", s.objs.HandleSendmsg},
		{"syscalls", "sys_enter_write", s.objs.HandleWrite},
	}
	for _, tp := range tps {
		l, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			s.tearDownAll()
			return nil, fmt.Errorf("attach tracepoint %s/%s: %w", tp.group, tp.name, err)
		}
		s.links = append(s.links, l)
		logger.Info("attached", "tracepoint", tp.group+"/"+tp.name)
	}

	// Kprobes on tcp_v{4,6}_connect catch TCP connects initiated via io_uring,
	// which skip sys_enter_connect entirely. Best-effort: if a symbol is
	// absent (very old kernel, unusual build), warn and continue — the
	// tracepoint still covers the syscall path.
	kps := []struct {
		symbol string
		prog   *ebpf.Program
	}{
		{"tcp_v4_connect", s.objs.HandleTcpV4Connect},
		{"tcp_v6_connect", s.objs.HandleTcpV6Connect},
	}
	for _, kp := range kps {
		l, err := link.Kprobe(kp.symbol, kp.prog, nil)
		if err != nil {
			logger.Warn("kprobe attach failed — io_uring TCP connects via this path won't be observed",
				"symbol", kp.symbol, "err", err)
			continue
		}
		s.links = append(s.links, l)
		logger.Info("attached", "kprobe", kp.symbol)
	}

	// libssl uprobe — best-effort. Failure here doesn't fail New; we log
	// and continue with only the other 7 probes active.
	libsslPath := opts.LibSSLPath
	if libsslPath == "" {
		libsslPath, _ = findLibSSL()
	}
	if libsslPath != "" {
		if exe, err := link.OpenExecutable(libsslPath); err != nil {
			logger.Warn("libssl not loadable for uprobe — TLS SNI events disabled",
				"path", libsslPath, "err", err,
				"hint", "shared libraries on Debian/Ubuntu/Kali are 644; try `sudo chmod +x "+libsslPath+"`")
		} else if upSSL, err := exe.Uprobe("SSL_ctrl", s.objs.HandleSslCtrl, nil); err != nil {
			logger.Warn("SSL_ctrl uprobe attach failed — TLS SNI events disabled",
				"path", libsslPath, "err", err)
		} else {
			s.links = append(s.links, upSSL)
			logger.Info("attached", "uprobe", "SSL_ctrl", "path", libsslPath)
		}
	} else {
		logger.Warn("libssl not found — TLS SNI events disabled")
	}

	rd, err := ringbuf.NewReader(s.objs.Events)
	if err != nil {
		s.tearDownAll()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	s.reader = rd

	return s, nil
}

// AddCgroup registers a cgroup for observation. Inserts the CGMAP entry
// and populates path_filter with the watched paths. Once this returns,
// events from processes in the cgroup will flow through the Events
// channel. Must be paired with a RemoveCgroup call on teardown.
func (s *Sensor) AddCgroup(opts AddCgroupOptions) error {
	if len(opts.WatchedPaths) == 0 {
		return errors.New("at least one WatchedPath is required for file events to fire")
	}
	s.cgroupsMu.Lock()
	defer s.cgroupsMu.Unlock()

	if _, exists := s.registered[opts.CgroupID]; exists {
		return fmt.Errorf("cgroup %d already registered", opts.CgroupID)
	}

	val := proto.CgmapValue{RunID: opts.RunID}
	if err := s.objs.Cgmap.Put(opts.CgroupID, val); err != nil {
		return fmt.Errorf("CGMAP.Put: %w", err)
	}

	added := make([]WatchedPath, 0, len(opts.WatchedPaths))
	for _, w := range opts.WatchedPaths {
		key, err := buildPathFilterKey(w.Prefix)
		if err != nil {
			s.rollbackPaths(opts.CgroupID, added)
			return fmt.Errorf("path_filter key for %q: %w", w.Prefix, err)
		}
		action := proto.PathActionKeep
		if w.CredTagged {
			action = proto.PathActionKeepCredTagged
		}
		if err := s.objs.PathFilter.Put(key, proto.PathFilterAction{Action: action}); err != nil {
			s.rollbackPaths(opts.CgroupID, added)
			return fmt.Errorf("path_filter.Put %q: %w", w.Prefix, err)
		}
		added = append(added, w)
		s.logger.Info("watching", "cgroup_id", opts.CgroupID, "prefix", w.Prefix, "cred_tagged", w.CredTagged)
	}

	s.registered[opts.CgroupID] = added
	cgN, pathN := s.mapCounts()
	s.logger.Info("cgroup registered",
		"cgroup_id", opts.CgroupID,
		"paths", len(added),
		"cgmap_total", cgN,
		"path_filter_total", pathN,
	)
	return nil
}

// DumpMisses returns the top N cgroup_ids that hit lookup_cgroup but
// didn't match any cgmap entry. Diagnostic — used to debug "missing
// events" cases.
func (s *Sensor) DumpMisses(top int) []MissEntry {
	if s.objs.CgmapMisses == nil {
		return nil
	}
	var out []MissEntry
	it := s.objs.CgmapMisses.Iterate()
	var k, v uint64
	for it.Next(&k, &v) {
		out = append(out, MissEntry{CgroupID: k, Count: v})
	}
	// Sort descending by count.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Count > out[i].Count {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if top > 0 && len(out) > top {
		out = out[:top]
	}
	return out
}

// MissEntry is one row of the cgmap-miss diagnostic dump.
type MissEntry struct {
	CgroupID uint64
	Count    uint64
}

// mapCounts returns the live entry counts of cgmap and path_filter.
// Diagnostic helper — used by AddCgroup/RemoveCgroup log lines so we
// can see whether map mutations actually took effect.
func (s *Sensor) mapCounts() (cgN, pathN int) {
	if s.objs.Cgmap != nil {
		it := s.objs.Cgmap.Iterate()
		var k uint64
		var v proto.CgmapValue
		for it.Next(&k, &v) {
			cgN++
		}
	}
	if s.objs.PathFilter != nil {
		it := s.objs.PathFilter.Iterate()
		var k proto.PathFilterKey
		var v proto.PathFilterAction
		for it.Next(&k, &v) {
			pathN++
		}
	}
	return
}

// RemoveCgroup deregisters a cgroup. Deletes the CGMAP entry and removes
// this cgroup's path_filter entries. Idempotent: returns nil if the
// cgroup is not registered.
func (s *Sensor) RemoveCgroup(cgroupID uint64) error {
	s.cgroupsMu.Lock()
	defer s.cgroupsMu.Unlock()

	paths, ok := s.registered[cgroupID]
	if !ok {
		return nil
	}
	delete(s.registered, cgroupID)

	if err := s.objs.Cgmap.Delete(cgroupID); err != nil {
		s.logger.Warn("CGMAP.Delete", "err", err, "cgroup_id", cgroupID)
	}
	for _, w := range paths {
		key, err := buildPathFilterKey(w.Prefix)
		if err != nil {
			continue
		}
		if err := s.objs.PathFilter.Delete(key); err != nil {
			s.logger.Warn("path_filter.Delete", "err", err, "prefix", w.Prefix)
		}
	}
	cgN, pathN := s.mapCounts()
	s.logger.Info("cgroup deregistered",
		"cgroup_id", cgroupID,
		"cgmap_total", cgN,
		"path_filter_total", pathN,
	)
	return nil
}

// rollbackPaths is called when AddCgroup fails partway through path
// insertion. Caller must hold cgroupsMu.
func (s *Sensor) rollbackPaths(cgroupID uint64, added []WatchedPath) {
	_ = s.objs.Cgmap.Delete(cgroupID)
	for _, w := range added {
		key, err := buildPathFilterKey(w.Prefix)
		if err != nil {
			continue
		}
		_ = s.objs.PathFilter.Delete(key)
	}
}

// Events returns a channel that yields decoded sensor events. The channel
// closes when ctx is canceled or when Close is called. Records that fail
// to decode are dropped with a warning to the logger.
func (s *Sensor) Events(ctx context.Context) <-chan Event {
	out := make(chan Event, 256)
	go func() {
		defer close(out)

		// Unblock reader.Read on context cancel.
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			select {
			case <-ctx.Done():
				_ = s.reader.Close()
			case <-stop:
			}
		}()

		for {
			rec, err := s.reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				s.logger.Warn("ringbuf.Read", "err", err)
				return
			}
			if len(rec.RawSample) < proto.HeaderTypeOffset+1 {
				s.logger.Warn("short record", "raw_len", len(rec.RawSample))
				continue
			}
			ev, err := decodeRecord(rec.RawSample)
			if err != nil {
				s.logger.Warn("decode event", "err", err, "raw_len", len(rec.RawSample))
				continue
			}
			// TLS dedup: tag the second source reporting the same (pid, sni).
			if tls, ok := ev.(*TLSSniEvent); ok && s.dedup != nil && tls.SNI != "" {
				src := tlsSourceName(tls.Source)
				if first := s.dedup.observe(tls.EventHeader().PID, tls.SNI, src, time.Now()); first != "" {
					tls.DuplicateOf = first
				}
			}
			// Connect dedup: drop kprobe events that follow a same-key
			// syscall event within the window (= the syscall-path duplicate).
			if conn, ok := ev.(*NetConnectEvent); ok && s.connDedup != nil && conn.DestIP != "" {
				if s.connDedup.observe(conn.EventHeader().PID, conn.Family, conn.Source, conn.DestIP, conn.DestPort, time.Now()) {
					continue
				}
			}
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// Drops returns the cumulative ringbuf reserve-fail count summed across
// all CPUs.
func (s *Sensor) Drops() (uint64, error) {
	if s.drops == nil {
		return 0, nil
	}
	var perCPU []uint64
	if err := s.drops.Lookup(uint32(0), &perCPU); err != nil {
		return 0, fmt.Errorf("drops_counter.Lookup: %w", err)
	}
	var total uint64
	for _, c := range perCPU {
		total += c
	}
	return total, nil
}

// Close detaches all probes, removes any lingering CGMAP entries,
// closes the ringbuf reader, and releases the BPF objects. Idempotent.
func (s *Sensor) Close() error {
	s.closeOnce.Do(s.tearDownAll)
	return s.closeErr
}

func (s *Sensor) tearDownAll() {
	if s.reader != nil {
		_ = s.reader.Close()
	}
	for _, l := range s.links {
		_ = l.Close()
	}
	s.links = nil

	s.cgroupsMu.Lock()
	for cgid := range s.registered {
		if s.objs.Cgmap != nil {
			_ = s.objs.Cgmap.Delete(cgid)
		}
	}
	s.registered = nil
	s.cgroupsMu.Unlock()

	if err := s.objs.Close(); err != nil && s.closeErr == nil {
		s.closeErr = err
	}
}

// decodeRecord peeks the event type discriminator at HeaderTypeOffset and
// dispatches to the matching decoder.
func decodeRecord(raw []byte) (Event, error) {
	switch proto.EventType(raw[proto.HeaderTypeOffset]) {
	case proto.EventTypeFileAccess:
		return decodeOpenatEvent(raw)
	case proto.EventTypeExec:
		return decodeExecEvent(raw)
	case proto.EventTypeNetConnect:
		return decodeNetConnectEvent(raw)
	case proto.EventTypeDNSQuery:
		return decodeDNSQueryEvent(raw)
	case proto.EventTypeTLSSNI:
		return decodeTLSSniEvent(raw)
	default:
		return nil, fmt.Errorf("unknown event type %d", raw[proto.HeaderTypeOffset])
	}
}

// --- helpers ---

func buildPathFilterKey(prefix string) (proto.PathFilterKey, error) {
	if len(prefix) == 0 || len(prefix) > proto.PathLen {
		return proto.PathFilterKey{}, fmt.Errorf("prefix length %d out of range (1..%d)", len(prefix), proto.PathLen)
	}
	var k proto.PathFilterKey
	k.PrefixLenBits = uint32(len(prefix)) * 8
	copy(k.Path[:], prefix)
	return k, nil
}

// ensureTracefs auto-mounts /sys/kernel/tracing if not already mounted.
// cilium/ebpf's link.Tracepoint() requires it.
func ensureTracefs(logger *slog.Logger) error {
	const tracefsPath = "/sys/kernel/tracing"
	if _, err := os.Stat(tracefsPath + "/events"); err == nil {
		return nil
	}
	logger.Info("mounting tracefs", "path", tracefsPath)
	if err := syscall.Mount("nodev", tracefsPath, "tracefs", 0, ""); err != nil {
		return fmt.Errorf("mount tracefs at %s: %w (hint: run as root or `sudo mount -t tracefs nodev %s` manually)", tracefsPath, err, tracefsPath)
	}
	if _, err := os.Stat(tracefsPath + "/events"); err != nil {
		return fmt.Errorf("tracefs mounted but %s/events still missing: %w", tracefsPath, err)
	}
	return nil
}

// findLibSSL locates the host's libssl.so file at runtime. Returns "" if
// none of the common install paths exist.
func findLibSSL() (string, error) {
	for _, p := range []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/usr/lib64/libssl.so.3",
		"/usr/lib64/libssl.so.1.1",
		"/usr/lib/libssl.so.3",
	} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("libssl.so.{3,1.1} not found")
}

func tlsSourceName(s uint8) string {
	return proto.TLSSourceName(s)
}

// tlsDedup tracks (pid, sni) tuples seen recently so we can flag the second
// mechanism reporting the same hostname as a duplicate. Single-goroutine —
// the Events reader is the only writer.
type tlsDedup struct {
	window time.Duration
	seen   map[string]struct {
		firstSource string
		ts          time.Time
	}
}

func newTLSDedup(window time.Duration) *tlsDedup {
	return &tlsDedup{
		window: window,
		seen: make(map[string]struct {
			firstSource string
			ts          time.Time
		}),
	}
}

// connectDedup collapses the (tracepoint, kprobe) pair emitted for one
// syscall-path TCP connect. Asymmetric semantics:
//
//   - syscall event (proto.NetSourceSyscall): record (pid, family, ip, port)
//     in the pending map; ALWAYS emit. Two syscall events for the same key
//     never collide because each represents a distinct connect() call.
//   - kprobe event (proto.NetSourceKprobe): if a matching syscall entry
//     exists within the window, drop this event (syscall-path duplicate);
//     otherwise emit (io_uring path — no syscall ever fired).
//
// Window is short (100 ms by default) — the tracepoint→kprobe gap is
// sub-millisecond, so 100 ms is generous slack against userspace reader
// scheduling jitter without risking a future syscall-path connect being
// misattributed.
type connectDedup struct {
	window  time.Duration
	pending map[string]time.Time
}

func newConnectDedup(window time.Duration) *connectDedup {
	return &connectDedup{
		window:  window,
		pending: make(map[string]time.Time),
	}
}

func (d *connectDedup) observe(pid uint32, family, source uint8, ip string, port uint16, now time.Time) (isDup bool) {
	if ip == "" {
		return false
	}
	// Opportunistic GC: drop any pending entry older than the window.
	// Bounded by per-cgroup connect rate × window — tiny in practice.
	for k, ts := range d.pending {
		if now.Sub(ts) > d.window {
			delete(d.pending, k)
		}
	}
	key := fmt.Sprintf("%d|%d|%s|%d", pid, family, ip, port)
	switch source {
	case proto.NetSourceSyscall:
		// Always emit; record so the upcoming kprobe pair is dropped.
		d.pending[key] = now
		return false
	case proto.NetSourceKprobe:
		ts, ok := d.pending[key]
		if ok && now.Sub(ts) <= d.window {
			// Pair consumed — drop this kprobe event and clear the marker
			// so a SECOND legitimate app-level connect to the same dest
			// (which would produce its own syscall+kprobe pair) isn't
			// suppressed by stale state.
			delete(d.pending, key)
			return true
		}
		// io_uring path — no preceding syscall event. Emit.
		return false
	default:
		// Unknown source — emit defensively rather than swallow.
		return false
	}
}

func (d *tlsDedup) observe(pid uint32, sni, source string, now time.Time) string {
	if sni == "" {
		return ""
	}
	for k, v := range d.seen {
		if now.Sub(v.ts) > d.window {
			delete(d.seen, k)
		}
	}
	key := fmt.Sprintf("%d|%s", pid, sni)
	if e, ok := d.seen[key]; ok && now.Sub(e.ts) <= d.window {
		return e.firstSource
	}
	d.seen[key] = struct {
		firstSource string
		ts          time.Time
	}{firstSource: source, ts: now}
	return ""
}
