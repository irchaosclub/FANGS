// Package proto defines the wire-level event types shared between the runner
// (which captures events from eBPF) and the orchestrator (which receives them
// over HTTPS). Field layouts mirror the C structs in the eBPF programs.
//
// SPDX-License-Identifier: Apache-2.0
package proto

// EventType identifies which payload follows the common EventHeader.
type EventType uint8

const (
	EventTypeFileAccess EventType = 1
	EventTypeExec       EventType = 2
	EventTypeNetConnect EventType = 3
	EventTypeDNSQuery   EventType = 4
	EventTypeTLSSNI     EventType = 5
)

// String renders the event type as the JSON-friendly snake_case name used
// in the smoke test output. Returns "unknown" for unrecognized values
// rather than panicking — useful when schemas evolve.
func (t EventType) String() string {
	switch t {
	case EventTypeFileAccess:
		return "file_access"
	case EventTypeExec:
		return "exec"
	case EventTypeNetConnect:
		return "net_connect"
	case EventTypeDNSQuery:
		return "dns_query"
	case EventTypeTLSSNI:
		return "tls_sni"
	default:
		return "unknown"
	}
}

// CommLen is the kernel's fixed comm width (TASK_COMM_LEN).
const CommLen = 16

// RunIDLen is the byte length of a ULID-encoded run identifier.
const RunIDLen = 16

// PathLen is the maximum path bytes captured in-kernel per FileAccess event.
const PathLen = 256

// ArgvNum is the number of argv slots captured per ExecEvent.
const ArgvNum = 8

// ArgvLen is the per-slot argv length budget in bytes.
const ArgvLen = 64

// AncestorsDepth is the number of process-ancestry levels captured on
// each ExecEvent. Index 0 = immediate parent.
const AncestorsDepth = 5

// Event tag bits — set on individual events by the kernel-side filter.
// Mirrored from EVENT_TAG_* constants in sensor.bpf.c.
const (
	EventTagInteresting uint8 = 1 << 0
	EventTagCredAccess  uint8 = 1 << 1
)

// HeaderTypeOffset is the byte offset of EventHeader.Type within an event
// payload. The reader peeks this byte to dispatch each ringbuf record to
// the right decoder without first parsing the full common header.
//
//	8 (TsNs) + 8 (CgroupID) + 16 (RunID) + 5*4 (PID..GID) + 16 (Comm) = 68
const HeaderTypeOffset = 68

// EventHeader is the common 72-byte prefix on every event emitted by the
// Sensor's eBPF probes. Mirrors `struct event_header` in sensor.bpf.c.
type EventHeader struct {
	TsNs     uint64
	CgroupID uint64
	RunID    [RunIDLen]byte
	PID      uint32
	TID      uint32
	PPID     uint32
	UID      uint32
	GID      uint32
	Comm     [CommLen]byte
	Type     uint8
	Tags     uint8
	_        [2]byte
}

// OpenatEvent mirrors `struct openat_event` in sensor.bpf.c.
// Size: 72 (header) + 4 + 4 + 2 + 1 + 1 + 256 = 340 bytes.
type OpenatEvent struct {
	Header    EventHeader
	DFD       int32
	Flags     int32
	PathLen   uint16
	Truncated uint8
	_         uint8
	Path      [PathLen]byte
}

// Ancestor mirrors `struct ancestor` in sensor.bpf.c.
// One process-tree node captured during an exec event.
type Ancestor struct {
	PID  uint32
	PPID uint32
	Comm [CommLen]byte
}

// ExecEvent mirrors `struct exec_event` in sensor.bpf.c.
// Size: 72 (header) + 1 + 3 (pad) + ArgvNum + ArgvNum*ArgvLen + PathLen + AncestorsDepth*sizeof(Ancestor)
//
//	= 72 + 4 + 8 + 512 + 256 + 5*24 = 972 bytes.
type ExecEvent struct {
	Header     EventHeader
	Argc       uint8
	_          [3]byte
	ArgvLens   [ArgvNum]uint8
	Argv       [ArgvNum * ArgvLen]byte
	BinaryPath [PathLen]byte
	Ancestors  [AncestorsDepth]Ancestor
}

// DestAddrLen is the byte width of the destination address field in network
// events. IPv4 occupies the lower 4 bytes; IPv6 uses all 16.
const DestAddrLen = 16

// DNSCaptureLen is the maximum bytes of raw DNS payload captured per query.
// Matches DNS_CAPTURE_LEN in sensor.bpf.c.
const DNSCaptureLen = 200

// Address-family values (kernel uapi). Stored in NetConnectEvent.Family /
// DnsQueryEvent.Family as uint8 (kernel field is u16, we narrow on emit).
const (
	AFInet  uint8 = 2
	AFInet6 uint8 = 10
)

// Connect-source values. Lets userspace tell apart the same connect()
// observed twice — once via sys_enter_connect (NetSourceSyscall) and
// once via tcp_v{4,6}_connect kprobe (NetSourceKprobe). Used by the
// connect dedup to drop the kprobe duplicate on the syscall path while
// preserving io_uring-initiated connects (kprobe with no syscall pair).
const (
	NetSourceSyscall uint8 = 1
	NetSourceKprobe  uint8 = 2
)

// NetConnectEvent mirrors `struct net_connect_event` in sensor.bpf.c.
// Size: 72 + 1 + 1 + 2 + 4 + 16 = 96 bytes.
type NetConnectEvent struct {
	Header   EventHeader
	Family   uint8
	Source   uint8 // NetSource*
	DestPort uint16
	Sockfd   uint32
	DestAddr [DestAddrLen]byte
}

// DnsQueryEvent mirrors `struct dns_query_event` in sensor.bpf.c.
// Size: 72 + 1 + 1 + 2 + 2 + 2 + 16 + 200 = 296 bytes.
//
// Query carries the raw bytes sent on the wire (DNS header + question section).
// Userspace parses the label-prefix-encoded query name — we keep that out of
// BPF to avoid a verifier-hostile recursive walk.
type DnsQueryEvent struct {
	Header   EventHeader
	Family   uint8
	_        [1]byte
	DestPort uint16
	QueryLen uint16
	_        [2]byte
	DestAddr [DestAddrLen]byte
	Query    [DNSCaptureLen]byte
}

// SNIMaxLen is the per-event maximum bytes captured for an SNI string.
// RFC 6066 caps server_name at 255 bytes; +1 for our NUL terminator.
const SNIMaxLen = 256

// TLS SNI capture mechanism. Three sources, deduped in userspace.
// Mirrored from TLS_SOURCE_* in sensor.bpf.c.
const (
	TLSSourceLibSSL         uint8 = 1 // uprobe on SSL_ctrl in libssl.so
	TLSSourceNodeInternal   uint8 = 2 // uprobe in Node binary's bundled TLS (future)
	TLSSourceTCPClientHello uint8 = 3 // kprobe parses ClientHello bytes (future)
)

// TLSSourceName turns the source enum into the JSON-friendly tag.
func TLSSourceName(s uint8) string {
	switch s {
	case TLSSourceLibSSL:
		return "libssl"
	case TLSSourceNodeInternal:
		return "node_internal"
	case TLSSourceTCPClientHello:
		return "tcp_clienthello"
	default:
		return "unknown"
	}
}

// TLSRawCapture is the max bytes of ClientHello payload captured per event
// when Source == TLSSourceTCPClientHello. Userspace parses the SNI extension
// from these bytes — keeping that out of BPF avoids verifier headaches with
// variable-length TLS extension walks.
const TLSRawCapture = 512

// TLSSniEvent mirrors `struct tls_sni_event` in sensor.bpf.c.
//
// Layout differs by Source:
//   - TLSSourceLibSSL:         SNI pre-parsed into SNI[]; RawPayload empty.
//   - TLSSourceTCPClientHello: SNI[] empty; RawPayload[0:RawPayloadLen]
//     holds the raw ClientHello bytes for the
//     userspace parser to extract the SNI.
//
// Size: 72 + 1 + 1 + 2 + 2 + 2 + 256 + 512 = 848 bytes.
type TLSSniEvent struct {
	Header        EventHeader
	Source        uint8
	_             [1]byte
	SniLen        uint16
	RawPayloadLen uint16
	_             [2]byte
	SNI           [SNIMaxLen]byte
	RawPayload    [TLSRawCapture]byte
}

// CgmapValue mirrors `struct cgmap_value` in sensor.bpf.c.
type CgmapValue struct {
	RunID [RunIDLen]byte
	Flags uint32
}

// PathFilterKey mirrors `struct path_filter_key` in sensor.bpf.c.
//
// PrefixLenBits is the length of the matchable prefix in BITS (not bytes).
// On insertion: byte length of the prefix × 8. On lookup the BPF program
// sets it to PathLen × 8 so the trie finds the longest matching entry.
type PathFilterKey struct {
	PrefixLenBits uint32
	Path          [PathLen]byte
}

// PathFilterAction values — match PATH_ACTION_* constants in sensor.bpf.c.
const (
	PathActionKeep           uint8 = 1
	PathActionKeepCredTagged uint8 = 2
)

// PathFilterAction mirrors `struct path_filter_action` in sensor.bpf.c.
type PathFilterAction struct {
	Action uint8
	_      [3]byte
}
