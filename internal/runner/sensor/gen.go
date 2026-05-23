// SPDX-License-Identifier: Apache-2.0
package sensor

// Generates sensor_bpfel.go + sensor_bpfel.o from bpf/sensor.bpf.c.
// Run via `go generate ./internal/runner/sensor/...` (or `make generate`).
//
// -cflags "-O2 -g": -O2 is required by the BPF verifier (-O0 produces
// unverifiable code); -g preserves BTF info for CO-RE.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -Werror" sensor bpf/sensor.bpf.c -- -I./bpf
