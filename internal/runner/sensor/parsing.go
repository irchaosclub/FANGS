// SPDX-License-Identifier: Apache-2.0
//
// Userspace parsers for raw protocol bytes captured by the eBPF probes.
// Keeping these out of BPF avoids verifier headaches with the variable-
// length walks involved (DNS labels, TLS extensions).
package sensor

import (
	"errors"
	"fmt"
	"strings"
)

// parseDNSQuestion extracts the first question name + qtype from a raw DNS
// query payload. Returns (qname, qtype, err). The query payload layout:
//
//	[0..1]   ID (transaction id)
//	[2..3]   flags
//	[4..5]   QDCOUNT (number of questions)
//	[6..7]   ANCOUNT
//	[8..9]   NSCOUNT
//	[10..11] ARCOUNT
//	[12..]   question section: labels (len-prefixed) + 0x00 + QTYPE(2) + QCLASS(2)
//
// Labels: each label starts with a length byte (0..63); 0x00 ends the name.
// Compression pointers (high two bits set) are NOT expected in a query
// (only in responses); if encountered, parse aborts with an error.
func parseDNSQuestion(buf []byte) (qname string, qtype uint16, err error) {
	if len(buf) < 12 {
		return "", 0, fmt.Errorf("dns header truncated (%d < 12)", len(buf))
	}
	qdcount := uint16(buf[4])<<8 | uint16(buf[5])
	if qdcount == 0 {
		return "", 0, errors.New("dns has no question (qdcount=0)")
	}

	// Walk labels starting at offset 12.
	i := 12
	var b strings.Builder
	for {
		if i >= len(buf) {
			return "", 0, errors.New("dns name overruns payload")
		}
		n := int(buf[i])
		i++
		if n == 0 {
			break
		}
		if n&0xC0 != 0 {
			return "", 0, errors.New("dns compression pointer in query")
		}
		if n > 63 {
			return "", 0, fmt.Errorf("dns label length %d > 63", n)
		}
		if i+n > len(buf) {
			return "", 0, errors.New("dns label overruns payload")
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.Write(buf[i : i+n])
		i += n
	}
	if i+4 > len(buf) {
		return "", 0, errors.New("dns qtype/qclass overruns payload")
	}
	qtype = uint16(buf[i])<<8 | uint16(buf[i+1])
	return b.String(), qtype, nil
}

// parseClientHelloSNI walks a TLS ClientHello byte stream and extracts the
// server_name extension's hostname. Returns ("", err) if the buffer doesn't
// hold a valid ClientHello with a server_name extension.
//
// TLS record + ClientHello layout (RFC 8446 / 5246):
//
//	[0]      ContentType (must be 0x16 = handshake)
//	[1..2]   ProtocolVersion (record layer; 0x03 0x01 for TLS 1.0+)
//	[3..4]   Record length (big-endian u16)
//	[5]      HandshakeType (must be 0x01 = ClientHello)
//	[6..8]   Handshake length (big-endian u24)
//	[9..10]  ClientVersion
//	[11..42] Random (32 bytes)
//	[43]     SessionID length, then SessionID
//	then     CipherSuites length (u16) + CipherSuites
//	then     CompressionMethods length (u8) + CompressionMethods
//	then     Extensions length (u16) + Extensions[]
//	each ext: ExtensionType (u16) + ExtensionData length (u16) + ExtensionData
//	  server_name extension (type 0):
//	    [0..1] server_name_list length
//	    [2]    NameType (0 = host_name)
//	    [3..4] HostName length
//	    [5..]  HostName bytes
func parseClientHelloSNI(buf []byte) (string, error) {
	if len(buf) < 43 {
		return "", fmt.Errorf("buffer too short for ClientHello (%d < 43)", len(buf))
	}
	if buf[0] != 0x16 {
		return "", fmt.Errorf("not a TLS handshake record (type 0x%02x)", buf[0])
	}
	if buf[5] != 0x01 {
		return "", fmt.Errorf("not a ClientHello (handshake type 0x%02x)", buf[5])
	}

	i := 43

	if i >= len(buf) {
		return "", errors.New("truncated at SessionID")
	}
	sidLen := int(buf[i])
	i += 1 + sidLen
	if i+2 > len(buf) {
		return "", errors.New("truncated at CipherSuites length")
	}

	csLen := int(buf[i])<<8 | int(buf[i+1])
	i += 2 + csLen
	if i >= len(buf) {
		return "", errors.New("truncated at CompressionMethods length")
	}

	cmLen := int(buf[i])
	i += 1 + cmLen
	if i+2 > len(buf) {
		return "", errors.New("truncated at Extensions length")
	}

	extTotal := int(buf[i])<<8 | int(buf[i+1])
	i += 2
	extEnd := i + extTotal
	if extEnd > len(buf) {
		extEnd = len(buf)
	}

	for i+4 <= extEnd {
		extType := int(buf[i])<<8 | int(buf[i+1])
		extLen := int(buf[i+2])<<8 | int(buf[i+3])
		i += 4
		if i+extLen > len(buf) {
			return "", fmt.Errorf("extension type %d overruns payload", extType)
		}
		if extType == 0 {
			if extLen < 5 {
				return "", errors.New("server_name extension too short")
			}
			nameType := buf[i+2]
			if nameType != 0 {
				return "", fmt.Errorf("server_name nameType %d not host_name", nameType)
			}
			nameLen := int(buf[i+3])<<8 | int(buf[i+4])
			nameStart := i + 5
			if nameStart+nameLen > len(buf) {
				return "", errors.New("server_name overruns payload")
			}
			return string(buf[nameStart : nameStart+nameLen]), nil
		}
		i += extLen
	}
	return "", errors.New("no server_name extension found")
}
