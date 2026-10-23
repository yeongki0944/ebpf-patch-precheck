# analysis EC2(AL2023, clang/bpftool/go 설치됨)에서 빌드
#   make            -> bin/patchscope-agent (정적 링크, 대상 서버에 compiler 불필요)
#   make vet test
GO      ?= /usr/local/go/bin/go
CLANG   ?= clang
BPFTOOL ?= bpftool
VERSION ?= $(shell git describe --always --dirty 2>/dev/null || echo dev)

BPF_SRC := bpf/patchscope.bpf.c
BPF_OBJ := internal/bpfload/patchscope.bpf.o
VMLINUX := bpf/vmlinux.h

.PHONY: all bpf vet test clean
all: bin/patchscope-agent

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) bpf/patchscope.h $(VMLINUX)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -Wall -Werror \
		-I bpf -I /usr/include -c $(BPF_SRC) -o $@

bpf: $(BPF_OBJ)

bin/patchscope-agent: $(BPF_OBJ) $(shell find . -name '*.go')
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath \
		-ldflags "-s -w -X main.version=$(VERSION)" -o $@ ./cmd/patchscope-agent

vet: $(BPF_OBJ)
	$(GO) vet ./...

test: $(BPF_OBJ)
	$(GO) test ./...

clean:
	rm -rf bin $(BPF_OBJ)
