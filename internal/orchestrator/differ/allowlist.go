// SPDX-License-Identifier: Apache-2.0
package differ

import (
	"fmt"
	"net"
	"sync"
)

// DefaultCDNAllowlist enumerates CIDR ranges considered infrastructure
// noise: large CDNs that round-robin their IPs per DNS query, producing
// "new IP" deviations on every install of a benign package.
//
// IPs in these ranges are dropped from net_new_destination fingerprints.
// Their identity (when present) is canonically carried by the
// net_new_https_host (SNI) and net_new_dns (qname) categories — those
// catch genuine destination changes regardless of which CDN edge
// happens to answer DNS today.
//
// DO NOT add a range here without considering the attack surface it
// hides: a malicious package CAN abuse a CDN to host C2 (e.g., uploads
// to a Cloudflare R2 bucket). The SNI/DNS-side coverage catches those
// because the hostname won't match baseline. We're only suppressing
// the redundant IP-side signal.
//
// Sources reviewed: cloudflare-ips.json (cloudflare.com/ips/),
// api.github.com/meta, gstatic.com hosting. Last refresh: 2026-05-22.
var DefaultCDNAllowlist = []string{
	// Cloudflare IPv4 (covers npm registry CDN, Discord, etc.)
	"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"104.16.0.0/13", "104.24.0.0/14",
	"108.162.192.0/18", "131.0.72.0/22",
	"141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
	"173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
	"197.234.240.0/22", "198.41.128.0/17",
	// GitHub
	"140.82.112.0/20", "143.55.64.0/20", "185.199.108.0/22",
	"192.30.252.0/22",
	// Google (gstatic, googleapis common CDN edges)
	"142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19",
	"172.253.0.0/16", "74.125.0.0/16",
	// Fastly
	"151.101.0.0/16", "199.232.0.0/16",
	// Amazon CloudFront (broad — could be tightened with regional lists later)
	"13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15",
	"54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16",
	"99.86.0.0/16", "204.246.164.0/22",
}

var (
	allowlistOnce sync.Once
	allowlistNets []*net.IPNet
)

func loadAllowlist() {
	for _, cidr := range DefaultCDNAllowlist {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("invalid CIDR in DefaultCDNAllowlist: %s: %v", cidr, err))
		}
		allowlistNets = append(allowlistNets, ipNet)
	}
}

// IsAllowlistedCDN reports whether the given IP string is in a known
// CDN range. Used by the Differ to suppress redundant IP-based
// net_new_destination fingerprints. Empty string returns false.
func IsAllowlistedCDN(ipStr string) bool {
	if ipStr == "" {
		return false
	}
	allowlistOnce.Do(loadAllowlist)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range allowlistNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
