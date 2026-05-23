// SPDX-License-Identifier: Apache-2.0
package main

// Generates sensor_bpfel.go (Go bindings) + sensor_bpfel.o (compiled BPF object)
// from sensor.bpf.c. Run via `go generate ./cmd/sensor-smoketest/...` (or `make bpf`).
//
// Why -target amd64: WSL2 / Hetzner / EC2 are x86_64. Cross-compilation handled in CI matrix later.
// Why -cflags "-O2 -g": -O2 is required by the BPF verifier (-O0 produces unverifiable code);
// -g preserves BTF info for CO-RE.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -Werror" sensor bpf/sensor.bpf.c -- -I./bpf
