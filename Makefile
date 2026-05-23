# FANGS — top-level Makefile
#
# Targets:
#   make vmlinux        Generate cmd/sensor-smoketest/bpf/vmlinux.h from this host's BTF.
#   make generate       Compile eBPF C + emit bpf2go bindings (depends on vmlinux).
#   make build          Build all Go binaries into ./bin/.
#   make test           Run all Go tests with -race.
#   make lint           gofmt + go vet.
#   make clean          Remove generated files and ./bin/.
#   make all            generate + build + test.
#
# Conventions:
#   - vmlinux.h is generated from the host kernel's BTF (per build env). Not checked in.
#   - bpf2go-generated .go files (*_bpfel.go) are checked in only if you want
#     consumers to skip the C build. We DON'T check them in by default — the
#     .gitignore excludes them and `make generate` rebuilds.

SHELL := /bin/bash
GO    ?= go
BPFTOOL ?= bpftool
CLANG ?= clang
GOFLAGS ?=

SMOKETEST_DIR := cmd/sensor-smoketest
SENSOR_DIR    := internal/runner/sensor
VMLINUX_H     := $(SENSOR_DIR)/bpf/vmlinux.h

BIN_DIR := bin
BINARIES := $(BIN_DIR)/sensor-smoketest $(BIN_DIR)/fangs-orchestrator $(BIN_DIR)/fangs-runner $(BIN_DIR)/fangs

.PHONY: all generate build test lint clean help vmlinux install-hooks

help:
	@awk 'BEGIN{FS=":.*##"; printf "Targets:\n"} /^[a-zA-Z_-]+:.*##/ {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: generate build test ## generate + build + test

vmlinux: $(VMLINUX_H) ## generate vmlinux.h from host BTF

$(VMLINUX_H):
	@echo ">> generating $@ from /sys/kernel/btf/vmlinux"
	@command -v $(BPFTOOL) >/dev/null || { echo "bpftool not found in PATH"; exit 1; }
	@test -r /sys/kernel/btf/vmlinux || { echo "/sys/kernel/btf/vmlinux not readable — kernel may lack BTF"; exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

generate: $(VMLINUX_H) ## compile eBPF C + emit bpf2go bindings
	@command -v $(CLANG) >/dev/null || { echo "clang not found in PATH"; exit 1; }
	cd $(SENSOR_DIR) && $(GO) generate ./...

build: generate ## build all Go binaries into ./bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -trimpath -o $(BIN_DIR)/sensor-smoketest    ./cmd/sensor-smoketest
	$(GO) build $(GOFLAGS) -trimpath -o $(BIN_DIR)/fangs-orchestrator ./cmd/fangs-orchestrator
	$(GO) build $(GOFLAGS) -trimpath -o $(BIN_DIR)/fangs-runner       ./cmd/fangs-runner
	$(GO) build $(GOFLAGS) -trimpath -o $(BIN_DIR)/fangs              ./cmd/fangs-cli

test: generate ## run all Go tests with -race
	$(GO) test -race -count=1 ./...

lint: ## gofmt -d + go vet
	@bad=$$(gofmt -l . 2>/dev/null | grep -v '/vmlinux.h$$' | grep -v '_bpfel.go$$' | grep -v '_bpfeb.go$$'); \
	if [ -n "$$bad" ]; then echo "gofmt issues:"; echo "$$bad"; exit 1; fi
	$(GO) vet ./...

clean: ## remove generated files and ./bin/
	rm -rf $(BIN_DIR)
	rm -f $(VMLINUX_H)
	find . -type f \( -name '*_bpfel.go' -o -name '*_bpfeb.go' -o -name '*_bpfel.o' -o -name '*_bpfeb.o' \) -delete

install-hooks: ## point git at ./githooks (gofmt check on every commit)
	git config core.hooksPath githooks
	@echo "✓ git hooks now sourced from ./githooks/"
	@ls -1 githooks/ | sed 's/^/  /'
