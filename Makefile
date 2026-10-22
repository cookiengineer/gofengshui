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
            $(BUILD_DIR)/testdata/size_swap

TESTLIBS := $(BUILD_DIR)/testdata/libgfsplugin.so

.PHONY: all build generate bpf test test-c bench clean fmt vet

all: build

build: generate
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -ldflags '-s -w' -o $(BIN) ./source/cmd/gofengshui

generate: $(BPF_GEN)

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_DIR)/gofengshui.bpf.c $(BPF_DIR)/gofengshui.h $(BPF_DIR)/vmlinux_min.h
	@mkdir -p $(dir $@)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_GEN): $(BPF_OBJ) source/tools/bpfgen/main.go
	$(GO) run ./source/tools/bpfgen -in $(BPF_OBJ) -out $@ -pkg ebpf -var bpfObject
	gofmt -w $@

test: generate
	$(GO) test ./source/...

bench: generate
	$(GO) test -run '^$$' -bench . -benchmem ./source/heap

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
	gofmt -w $$(find source -name '*.go' ! -name 'object_generated.go')

vet: generate
	$(GO) vet ./source/...
