// SPDX-License-Identifier: Apache-2.0
package sensor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

// Event is the typed union of all sensor event types. Consumers use a
// Go type switch (`switch e := evt.(type)`) to dispatch.
type Event interface {
	// EventType returns the discriminator for this event variant.
	EventType() proto.EventType
	// EventHeader returns the common header (timestamp, pid, comm, ...)
	// shared by all event variants.
	EventHeader() proto.EventHeader
}

// --- typed concrete events ---

// FileAccessEvent wraps proto.OpenatEvent and adds parsed string fields
// the Differ uses for baseline aggregation.
type FileAccessEvent struct {
	proto.OpenatEvent
	PathName string // null-terminated string parsed from Path[:PathLen]
	CommStr  string // null-terminated string parsed from Header.Comm
}

func (e FileAccessEvent) EventType() proto.EventType     { return proto.EventTypeFileAccess }
func (e FileAccessEvent) EventHeader() proto.EventHeader { return e.OpenatEvent.Header }

// ExecEvent wraps proto.ExecEvent. BinaryPath, Argv, AncestorComms hold
// the parsed-string versions of the raw byte arrays from the kernel.
type ExecEvent struct {
	proto.ExecEvent
	BinaryPathStr string   // parsed BinaryPath
	ArgvStrs      []string // argv parsed from Argv blob using ArgvLens
	CommStr       string   // parsed Header.Comm
	AncestorComms []string // parsed Ancestors[i].Comm
}

func (e ExecEvent) EventType() proto.EventType     { return proto.EventTypeExec }
func (e ExecEvent) EventHeader() proto.EventHeader { return e.ExecEvent.Header }

// NetConnectEvent wraps proto.NetConnectEvent. DestIP is the parsed
// destination as a dotted-quad / IPv6 string for queryability.
type NetConnectEvent struct {
	proto.NetConnectEvent
	DestIP  string // "1.2.3.4" or "[::1]" form
	CommStr string // parsed Header.Comm
}

func (e NetConnectEvent) EventType() proto.EventType     { return proto.EventTypeNetConnect }
func (e NetConnectEvent) EventHeader() proto.EventHeader { return e.NetConnectEvent.Header }

// DNSQueryEvent wraps proto.DnsQueryEvent and adds parsed-name fields.
//
// QName/QType are populated from a successful userspace parse of the raw
// query payload. ParseErr is non-nil when parsing failed; in that case
// QName == "" and the consumer should fall back to inspecting raw bytes
// via proto.DnsQueryEvent.Query.
type DNSQueryEvent struct {
	proto.DnsQueryEvent
	QName    string
	QType    uint16
	DestIP   string // parsed destination
	CommStr  string // parsed Header.Comm
	ParseErr error
}

func (e DNSQueryEvent) EventType() proto.EventType     { return proto.EventTypeDNSQuery }
func (e DNSQueryEvent) EventHeader() proto.EventHeader { return e.DnsQueryEvent.Header }

// TLSSniEvent wraps proto.TLSSniEvent. For source=tcp_clienthello the SNI
// is parsed from RawPayload in userspace; for source=libssl it comes
// pre-populated from the BPF probe. SNI is the unified string regardless
// of source. DuplicateOf names the earlier source that already reported
// this (pid, sni) within the dedup window, or "" if this is the first.
type TLSSniEvent struct {
	proto.TLSSniEvent
	SNI         string
	DuplicateOf string
	SourceName  string // "libssl" | "tcp_clienthello" | ...
	CommStr     string // parsed Header.Comm
	ParseErr    error
}

func (e TLSSniEvent) EventType() proto.EventType     { return proto.EventTypeTLSSNI }
func (e TLSSniEvent) EventHeader() proto.EventHeader { return e.TLSSniEvent.Header }

// --- decoders ---

func decodeOpenatEvent(raw []byte) (*FileAccessEvent, error) {
	var ev proto.OpenatEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return nil, fmt.Errorf("binary.Read OpenatEvent: %w (got %d bytes)", err, len(raw))
	}
	pathEnd := int(ev.PathLen)
	if pathEnd > len(ev.Path) {
		pathEnd = len(ev.Path)
	}
	return &FileAccessEvent{
		OpenatEvent: ev,
		PathName:    cstring(ev.Path[:pathEnd]),
		CommStr:     cstring(ev.Header.Comm[:]),
	}, nil
}

func decodeExecEvent(raw []byte) (*ExecEvent, error) {
	var ev proto.ExecEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return nil, fmt.Errorf("binary.Read ExecEvent: %w (got %d bytes)", err, len(raw))
	}
	argv := make([]string, 0, ev.Argc)
	for i := 0; i < int(ev.Argc) && i < proto.ArgvNum; i++ {
		off := i * proto.ArgvLen
		end := off + int(ev.ArgvLens[i])
		if end > len(ev.Argv) {
			end = len(ev.Argv)
		}
		argv = append(argv, cstring(ev.Argv[off:end]))
	}
	ancestors := make([]string, 0, proto.AncestorsDepth)
	for i := 0; i < proto.AncestorsDepth; i++ {
		if ev.Ancestors[i].PID == 0 {
			break
		}
		ancestors = append(ancestors, cstring(ev.Ancestors[i].Comm[:]))
	}
	return &ExecEvent{
		ExecEvent:     ev,
		BinaryPathStr: cstring(ev.BinaryPath[:]),
		ArgvStrs:      argv,
		CommStr:       cstring(ev.Header.Comm[:]),
		AncestorComms: ancestors,
	}, nil
}

func decodeNetConnectEvent(raw []byte) (*NetConnectEvent, error) {
	var ev proto.NetConnectEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return nil, fmt.Errorf("binary.Read NetConnectEvent: %w (got %d bytes)", err, len(raw))
	}
	return &NetConnectEvent{
		NetConnectEvent: ev,
		DestIP:          formatDestIP(ev.Family, ev.DestAddr),
		CommStr:         cstring(ev.Header.Comm[:]),
	}, nil
}

func decodeDNSQueryEvent(raw []byte) (*DNSQueryEvent, error) {
	var ev proto.DnsQueryEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return nil, fmt.Errorf("binary.Read DnsQueryEvent: %w (got %d bytes)", err, len(raw))
	}
	out := &DNSQueryEvent{
		DnsQueryEvent: ev,
		DestIP:        formatDestIP(ev.Family, ev.DestAddr),
		CommStr:       cstring(ev.Header.Comm[:]),
	}
	qend := int(ev.QueryLen)
	if qend > len(ev.Query) {
		qend = len(ev.Query)
	}
	qname, qtype, err := parseDNSQuestion(ev.Query[:qend])
	if err != nil {
		out.ParseErr = err
	} else {
		out.QName = qname
		out.QType = qtype
	}
	return out, nil
}

func decodeTLSSniEvent(raw []byte) (*TLSSniEvent, error) {
	var ev proto.TLSSniEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return nil, fmt.Errorf("binary.Read TLSSniEvent: %w (got %d bytes)", err, len(raw))
	}
	out := &TLSSniEvent{
		TLSSniEvent: ev,
		SourceName:  proto.TLSSourceName(ev.Source),
		CommStr:     cstring(ev.Header.Comm[:]),
	}
	switch ev.Source {
	case proto.TLSSourceLibSSL, proto.TLSSourceNodeInternal:
		sniEnd := int(ev.SniLen)
		if sniEnd > len(ev.SNI) {
			sniEnd = len(ev.SNI)
		}
		out.SNI = cstring(ev.SNI[:sniEnd])

	case proto.TLSSourceTCPClientHello:
		end := int(ev.RawPayloadLen)
		if end > len(ev.RawPayload) {
			end = len(ev.RawPayload)
		}
		sni, err := parseClientHelloSNI(ev.RawPayload[:end])
		if err != nil {
			out.ParseErr = err
		} else {
			out.SNI = sni
		}
	}
	return out, nil
}

// cstring returns the substring of b up to the first NUL byte, or the
// whole slice if no NUL is present. Used to convert C fixed-size char
// arrays into Go strings.
func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// formatDestIP turns the kernel's 16-byte DestAddr into a readable IP
// string. For AF_INET only the first 4 bytes are meaningful; for AF_INET6
// all 16. Unknown families return "" so downstream queries can filter.
func formatDestIP(family uint8, addr [proto.DestAddrLen]byte) string {
	switch family {
	case proto.AFInet:
		return net.IP(addr[:4]).String()
	case proto.AFInet6:
		return net.IP(addr[:]).String()
	default:
		return ""
	}
}
