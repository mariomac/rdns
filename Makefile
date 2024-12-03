# Main binary configuration
CMD ?= rdns
MAIN_GO_FILE ?= cmd/$(CMD)/main.go
GOOS ?= linux
GOARCH ?= amd64

LOCAL_GENERATOR_IMAGE ?= ghcr.io/grafana/beyla-generator:main


# BPF code generator dependencies
CILIUM_EBPF_VERSION := v0.16.0
CLANG ?= clang
# restore -Werror
CFLAGS := -O2 -g -Wall $(CFLAGS)

.PHONY: prereqs
prereqs:
	@echo "### Check if prerequisites are met, and installing missing dependencies"
	test -f $(shell go env GOPATH)/bin/bpf2go || go install github.com/cilium/ebpf/cmd/bpf2go@${CILIUM_EBPF_VERSION}

# As generated artifacts are part of the code repo (pkg/ebpf packages), you don't have
# to run this target for each build. Only when you change the C code inside the bpf folder.
# You might want to use the docker-generate target instead of this.
.PHONY: generate
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: prereqs
	@echo "### Generating BPF Go bindings"
	go generate ./pkg/...

.PHONY: docker-generate
docker-generate:
	docker run --rm -v $(shell pwd):/src $(LOCAL_GENERATOR_IMAGE)

.PHONY: compile
compile:
	@echo "### Compiling project"
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -mod vendor -ldflags -a -o bin/$(CMD) $(MAIN_GO_FILE)
