GO        ?= go
CLANG     ?= clang
CC        ?= gcc
CXX       ?= g++
GOFLAGS   ?=
BUILD_DIR := build
BPF_DIR   := bpf
BPF_OBJ   := $(BUILD_DIR)/bpf/gofengshui.bpf.o
BPF_GEN   := source/ebpf/object_generated.go
BIN       := $(BUILD_DIR)/gofengshui
VERSION   ?= 0.1.0
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -s -w \
             -X gofengshui/cli.Version=$(VERSION) \
             -X gofengshui/cli.Commit=$(COMMIT) \
             -X gofengshui/cli.BuildDate=$(BUILD_DATE)
DIST_NAME := gofengshui-$(VERSION)-linux-x86_64
DIST_DIR  := $(BUILD_DIR)/dist/$(DIST_NAME)

BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf \
              -D__TARGET_ARCH_x86 \
              -I/usr/include/x86_64-linux-gnu -I/usr/include -I$(BPF_DIR)

TESTBINS := $(BUILD_DIR)/testdata/alloc_loop \
            $(BUILD_DIR)/testdata/double_free \
            $(BUILD_DIR)/testdata/uaf \
            $(BUILD_DIR)/testdata/overflow \
            $(BUILD_DIR)/testdata/rop_sink \
            $(BUILD_DIR)/testdata/alloc_fail \
            $(BUILD_DIR)/testdata/crash \
            $(BUILD_DIR)/testdata/threads \
            $(BUILD_DIR)/testdata/attach_threads \
            $(BUILD_DIR)/testdata/fork_exec \
            $(BUILD_DIR)/testdata/backfill \
            $(BUILD_DIR)/testdata/poison \
            $(BUILD_DIR)/testdata/alloc_once \
            $(BUILD_DIR)/testdata/syscall_uaf \
            $(BUILD_DIR)/testdata/realloc_churn \
            $(BUILD_DIR)/testdata/arena_backfill \
            $(BUILD_DIR)/testdata/watch_alloc \
            $(BUILD_DIR)/testdata/metadata \
            $(BUILD_DIR)/testdata/uaf_direct \
            $(BUILD_DIR)/testdata/dlopen_alloc \
            $(BUILD_DIR)/testdata/cxx_alloc \
            $(BUILD_DIR)/testdata/size_swap \
            $(BUILD_DIR)/testdata/tcache_introspect \
            $(BUILD_DIR)/testdata/tcache_threads \
            $(BUILD_DIR)/testdata/oom

TESTLIBS := $(BUILD_DIR)/testdata/libgfsplugin.so
E2E_DIR := e2e-tests
E2E_LOG := $(BUILD_DIR)/logs/e2e-$$(date +%Y%m%d-%H%M%S).log
TOOLCHAIN_DIR := toolchain
TOOLCHAIN_BIN := $(BUILD_DIR)/toolchain

.PHONY: all build generate bpf test test-c bench dist clean fmt vet e2e e2e-image e2e-clean \
        toolchain toolchain-test toolchain-vet check-env dev-image dev-container host-agent fix-permissions

all: build

build: generate
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) -C source build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' -o ../$(BIN) ./cmd/gofengshui

generate: $(BPF_GEN)

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_DIR)/gofengshui.bpf.c $(BPF_DIR)/gofengshui.h $(BPF_DIR)/vmlinux_min.h
	@mkdir -p $(dir $@)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_GEN): $(BPF_OBJ) source/tools/bpfgen/main.go
	$(GO) -C source run ./tools/bpfgen -in ../$(BPF_OBJ) -out ebpf/object_generated.go -pkg ebpf -var bpfObject
	gofmt -w $@

test: generate toolchain-test
	$(GO) -C source test ./...

toolchain:
	@mkdir -p $(TOOLCHAIN_BIN)
	$(GO) -C $(TOOLCHAIN_DIR) build -trimpath -o ../$(TOOLCHAIN_BIN)/ ./...

toolchain-test:
	$(GO) -C $(TOOLCHAIN_DIR) test ./...

toolchain-vet:
	$(GO) -C $(TOOLCHAIN_DIR) vet ./...

check-env:
	$(GO) -C $(E2E_DIR) run ./cmd/hostinfo

dev-image: toolchain
	./$(TOOLCHAIN_BIN)/build-image

dev-container: toolchain
	./$(TOOLCHAIN_BIN)/dev-container

host-agent: toolchain
	./$(TOOLCHAIN_BIN)/host-agent

fix-permissions: toolchain
	./$(TOOLCHAIN_BIN)/fix-permissions

e2e: SHELL := /bin/bash
e2e:
	@test "$$(id -u)" = "0" || { echo "e2e tests must run as root; use: sudo -E make e2e"; exit 1; }
	@mkdir -p $(BUILD_DIR)/logs
	@log="$$(pwd)/$(E2E_LOG)"; ln -sfn "$$log" $(BUILD_DIR)/logs/latest-e2e.log; \
	  $(GO) -C $(E2E_DIR) test -count=1 -p 1 -timeout=60m -v ./... 2>&1 | tee -a "$$log"; status=$${PIPESTATUS[0]}; \
	  chown -R "$${SUDO_UID:-0}:$${SUDO_GID:-0}" $(BUILD_DIR)/e2e $(BUILD_DIR)/logs $(BUILD_DIR)/gofengshui $(BUILD_DIR)/bpf source/ebpf/object_generated.go 2>/dev/null || true; \
	  exit $$status

e2e-image: dev-image

e2e-clean:
	@test "$$(id -u)" = "0" || { echo "run: sudo -E make e2e-clean"; exit 1; }
	-podman ps -aq --filter label=gofengshui.e2e=1 | xargs -r podman rm -f
	rm -rf $(BUILD_DIR)/e2e

bench: generate
	$(GO) -C source test -run '^$$' -bench . -benchmem ./heap

dist: build
	rm -rf $(DIST_DIR)
	mkdir -p $(DIST_DIR)/docs $(DIST_DIR)/toolchain
	cp -p $(BIN) $(DIST_DIR)/
	cp -p docs/*.md $(DIST_DIR)/docs/
	cp -a $(TOOLCHAIN_DIR)/. $(DIST_DIR)/toolchain/
	tar -C $(BUILD_DIR)/dist -czf $(BUILD_DIR)/dist/$(DIST_NAME).tar.gz $(DIST_NAME)
	cd $(BUILD_DIR)/dist && sha256sum $(DIST_NAME).tar.gz > $(DIST_NAME).tar.gz.sha256
	@echo "release: $(BUILD_DIR)/dist/$(DIST_NAME).tar.gz"

test-c: $(TESTBINS) $(TESTLIBS)

$(BUILD_DIR)/testdata/%: source/testdata/c/%.c source/testdata/c/gfs_harness.h
	@mkdir -p $(dir $@)
	$(CC) -g -O0 -fno-omit-frame-pointer -fno-stack-protector -no-pie -pthread -o $@ $<

$(BUILD_DIR)/testdata/libgfsplugin.so: source/testdata/c/gfsplugin.c
	@mkdir -p $(dir $@)
	$(CC) -g -O0 -shared -fPIC -o $@ $<

$(BUILD_DIR)/testdata/cxx_alloc: source/testdata/c/cxx_alloc.cpp source/testdata/c/gfs_harness.h
	@mkdir -p $(dir $@)
	$(CXX) -g -O0 -fno-omit-frame-pointer -fno-stack-protector -no-pie -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(BPF_GEN)

fmt:
	gofmt -w $$(find source e2e-tests toolchain -name '*.go' ! -name 'object_generated.go')

vet: generate toolchain-vet
	$(GO) -C source vet ./...
