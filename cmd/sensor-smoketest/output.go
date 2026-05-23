// SPDX-License-Identifier: Apache-2.0
//
// JSON output shapes for the smoke test. Each sensor.Event type maps to a
// human-friendly JSON line. Production runner emits structured records over
// the protocol instead — these shapes are smoke-test convenience.
package main

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/irchaosclub/FANGS/internal/runner/sensor"
	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

// headerJSON is the common prefix on every emitted event.
type headerJSON struct {
	TsRel    string   `json:"ts_rel"`
	Type     string   `json:"event_type"`
	RunID    string   `json:"run_id"`
	CgroupID uint64   `json:"cgroup_id"`
	PID      uint32   `json:"pid"`
	TID      uint32   `json:"tid"`
	PPID     uint32   `json:"ppid"`
	UID      uint32   `json:"uid"`
	GID      uint32   `json:"gid"`
	Comm     string   `json:"comm"`
	Tags     []string `json:"tags,omitempty"`
}

func jsonifyHeader(ev sensor.Event, start time.Time) headerJSON {
	h := ev.EventHeader()
	return headerJSON{
		TsRel:    fmt.Sprintf("%.6f", time.Since(start).Seconds()),
		Type:     ev.EventType().String(),
		RunID:    hex.EncodeToString(h.RunID[:]),
		CgroupID: h.CgroupID,
		PID:      h.PID,
		TID:      h.TID,
		PPID:     h.PPID,
		UID:      h.UID,
		GID:      h.GID,
		Comm:     cstring(h.Comm[:]),
		Tags:     decodeTags(h.Tags),
	}
}

type openatJSON struct {
	headerJSON
	DFD       int32  `json:"dfd"`
	Flags     int32  `json:"flags"`
	Path      string `json:"path"`
	Truncated bool   `json:"truncated,omitempty"`
}

type ancestorJSON struct {
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	Comm string `json:"comm"`
}

type execJSON struct {
	headerJSON
	BinaryPath string         `json:"binary_path"`
	Argc       uint8          `json:"argc"`
	Argv       []string       `json:"argv"`
	Ancestors  []ancestorJSON `json:"ancestors,omitempty"`
}

type netConnectJSON struct {
	headerJSON
	Family   string `json:"family"`
	DestAddr string `json:"dest_addr"`
	DestPort uint16 `json:"dest_port"`
	Sockfd   uint32 `json:"sockfd"`
}

type dnsQueryJSON struct {
	headerJSON
	Family   string `json:"family"`
	DestAddr string `json:"dest_addr"`
	DestPort uint16 `json:"dest_port"`
	QueryLen uint16 `json:"query_len"`
	QName    string `json:"qname,omitempty"`
	QType    uint16 `json:"qtype,omitempty"`
	ParseErr string `json:"parse_err,omitempty"`
}

type tlsSniJSON struct {
	headerJSON
	Source      string `json:"source"`
	SNI         string `json:"sni,omitempty"`
	DuplicateOf string `json:"duplicate_of,omitempty"`
	ParseErr    string `json:"parse_err,omitempty"`
}

// eventToJSON shapes any sensor.Event into the matching wire form.
// Returns `any` so json.Encoder can pick the concrete type.
func eventToJSON(ev sensor.Event, start time.Time) any {
	switch e := ev.(type) {
	case *sensor.FileAccessEvent:
		pathEnd := int(e.PathLen)
		if pathEnd > len(e.Path) {
			pathEnd = len(e.Path)
		}
		return openatJSON{
			headerJSON: jsonifyHeader(ev, start),
			DFD:        e.DFD,
			Flags:      e.Flags,
			Path:       cstring(e.Path[:pathEnd]),
			Truncated:  e.Truncated == 1,
		}

	case *sensor.ExecEvent:
		out := execJSON{
			headerJSON: jsonifyHeader(ev, start),
			BinaryPath: cstring(e.BinaryPath[:]),
			Argc:       e.Argc,
			Argv:       []string{},
		}
		for i := 0; i < int(e.Argc) && i < proto.ArgvNum; i++ {
			start := i * proto.ArgvLen
			length := int(e.ArgvLens[i])
			if length > proto.ArgvLen {
				length = proto.ArgvLen
			}
			out.Argv = append(out.Argv, cstring(e.Argv[start:start+length]))
		}
		for _, a := range e.Ancestors {
			if a.PID == 0 && a.PPID == 0 {
				break
			}
			out.Ancestors = append(out.Ancestors, ancestorJSON{
				PID:  a.PID,
				PPID: a.PPID,
				Comm: cstring(a.Comm[:]),
			})
		}
		return out

	case *sensor.NetConnectEvent:
		return netConnectJSON{
			headerJSON: jsonifyHeader(ev, start),
			Family:     familyString(e.Family),
			DestAddr:   formatIP(e.Family, e.DestAddr[:]),
			DestPort:   e.DestPort,
			Sockfd:     e.Sockfd,
		}

	case *sensor.DNSQueryEvent:
		out := dnsQueryJSON{
			headerJSON: jsonifyHeader(ev, start),
			Family:     familyString(e.Family),
			DestAddr:   formatIP(e.Family, e.DestAddr[:]),
			DestPort:   e.DestPort,
			QueryLen:   e.QueryLen,
			QName:      e.QName,
			QType:      e.QType,
		}
		if e.ParseErr != nil {
			out.ParseErr = e.ParseErr.Error()
		}
		return out

	case *sensor.TLSSniEvent:
		out := tlsSniJSON{
			headerJSON:  jsonifyHeader(ev, start),
			Source:      proto.TLSSourceName(e.Source),
			SNI:         e.SNI,
			DuplicateOf: e.DuplicateOf,
		}
		if e.ParseErr != nil {
			out.ParseErr = e.ParseErr.Error()
		}
		return out
	}
	return map[string]any{"event_type": "unknown"}
}

// --- helpers ---

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func familyString(f uint8) string {
	switch f {
	case proto.AFInet:
		return "ipv4"
	case proto.AFInet6:
		return "ipv6"
	default:
		return fmt.Sprintf("family_%d", f)
	}
}

func formatIP(family uint8, addr []byte) string {
	switch family {
	case proto.AFInet:
		if len(addr) < 4 {
			return ""
		}
		return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
	case proto.AFInet6:
		if len(addr) < 16 {
			return ""
		}
		return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			uint16(addr[0])<<8|uint16(addr[1]),
			uint16(addr[2])<<8|uint16(addr[3]),
			uint16(addr[4])<<8|uint16(addr[5]),
			uint16(addr[6])<<8|uint16(addr[7]),
			uint16(addr[8])<<8|uint16(addr[9]),
			uint16(addr[10])<<8|uint16(addr[11]),
			uint16(addr[12])<<8|uint16(addr[13]),
			uint16(addr[14])<<8|uint16(addr[15]),
		)
	default:
		return ""
	}
}

func decodeTags(b uint8) []string {
	var out []string
	if b&proto.EventTagInteresting != 0 {
		out = append(out, "interesting")
	}
	if b&proto.EventTagCredAccess != 0 {
		out = append(out, "cred_access")
	}
	return out
}
