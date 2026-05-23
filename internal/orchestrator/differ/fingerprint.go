// SPDX-License-Identifier: Apache-2.0
package differ

import (
	"encoding/json"
	"fmt"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

// ExtractFingerprints is the legacy entry point — equivalent to
// ExtractFingerprintsWith called with a nil filter (only the hardcoded
// CDN allowlist applies). Kept for callers that don't need operator
// allowlist support.
func ExtractFingerprints(events []storage.EventRow) []Fingerprint {
	return ExtractFingerprintsWith(events, nil)
}

// ExtractFingerprintsWith walks the run's events and emits one
// Fingerprint per distinct (category, normalized-value) pair, with
// operator-allowlist filtering applied. Pass nil for filter to skip
// the operator layer (the hardcoded CDN allowlist still applies via
// IsAllowlistedCDN inside the extractors).
//
// Events whose JSON payload fails to decode are skipped with no error
// — the caller's slog handles surfacing them.
func ExtractFingerprintsWith(events []storage.EventRow, filter *Filter) []Fingerprint {
	bucket := make(map[string]*Fingerprint)
	addUnique := func(cat Category, value string, evtID int64) {
		if value == "" {
			return
		}
		key := string(cat) + "|" + value
		if fp, ok := bucket[key]; ok {
			fp.Count++
			return
		}
		bucket[key] = &Fingerprint{
			Category:   cat,
			Value:      value,
			Count:      1,
			FirstEvtID: evtID,
		}
	}

	for _, e := range events {
		switch e.Type {
		case "file_access":
			extractFileAccess(e, addUnique, filter)
		case "exec":
			extractExec(e, addUnique)
		case "net_connect":
			extractNetConnect(e, addUnique, filter)
		case "dns_query":
			extractDNS(e, addUnique)
		case "tls_sni":
			extractTLSSNI(e, addUnique, filter)
		}
	}

	out := make([]Fingerprint, 0, len(bucket))
	for _, fp := range bucket {
		out = append(out, *fp)
	}
	return out
}

// --- per-type extraction ---

func extractFileAccess(e storage.EventRow, add func(Category, string, int64), filter *Filter) {
	var p struct {
		PathName string `json:"PathName"`
		Flags    int32  `json:"Flags"`
	}
	if err := json.Unmarshal(e.Data, &p); err != nil {
		return
	}
	if p.PathName == "" {
		return
	}
	norm := NormalizePath(p.PathName)
	if filter.SuppressPath(norm) {
		return
	}
	// O_WRONLY=1, O_RDWR=2, O_CREAT=64. Treat any write-intent open as a write.
	const oWrOnly, oRdWr, oCreat = 1, 2, 64
	isWrite := (p.Flags&oWrOnly != 0) || (p.Flags&oRdWr != 0) || (p.Flags&oCreat != 0)
	if isWrite {
		add(CatFSPathWrite, norm, e.ID)
	} else {
		add(CatFSPathRead, norm, e.ID)
	}
}

func extractExec(e storage.EventRow, add func(Category, string, int64)) {
	var p struct {
		BinaryPathStr string `json:"BinaryPathStr"`
	}
	if err := json.Unmarshal(e.Data, &p); err != nil {
		return
	}
	add(CatProcExec, NormalizeBinaryPath(p.BinaryPathStr), e.ID)
}

func extractNetConnect(e storage.EventRow, add func(Category, string, int64), filter *Filter) {
	var p struct {
		DestIP   string `json:"DestIP"`
		DestPort uint16 `json:"DestPort"`
	}
	if err := json.Unmarshal(e.Data, &p); err != nil {
		return
	}
	if p.DestIP == "" {
		return
	}
	// Operator-or-default CIDR allowlist: known CDN infra ranges round-
	// robin their IPs per DNS query, and operators can add internal
	// networks. IPs in any allowed CIDR are dropped from
	// net_new_destination — their identity is canonically carried by SNI
	// or DNS.
	//
	// IMPORTANT: this is NOT a blanket port-443 suppression. Connections
	// to non-allowlisted IPs on 443 are still flagged (real malware
	// commonly uses 443 to legitimate-looking destinations).
	if filter.SuppressIP(p.DestIP) || IsAllowlistedCDN(p.DestIP) {
		return
	}
	dest := fmt.Sprintf("%s:%d", p.DestIP, p.DestPort)
	add(CatNetDestination, NormalizeDestination(dest), e.ID)
}

func extractDNS(e storage.EventRow, add func(Category, string, int64)) {
	var p struct {
		QName string `json:"QName"`
	}
	if err := json.Unmarshal(e.Data, &p); err != nil {
		return
	}
	add(CatNetDNS, NormalizeDNS(p.QName), e.ID)
}

func extractTLSSNI(e storage.EventRow, add func(Category, string, int64), filter *Filter) {
	var p struct {
		SNI string `json:"SNI"`
	}
	if err := json.Unmarshal(e.Data, &p); err != nil {
		return
	}
	norm := NormalizeSNI(p.SNI)
	if filter.SuppressSNI(norm) {
		return
	}
	add(CatNetHTTPSHost, norm, e.ID)
}
