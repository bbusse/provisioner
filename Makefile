GO ?= go
OUT ?= build
PODMAN ?= podman
LDFLAGS := -s -w

.PHONY: build linux mips test vet image

build:
	$(GO) build -trimpath -ldflags='$(LDFLAGS)' -o $(OUT)/provisioner ./cmd/provisioner

linux:
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath -ldflags='$(LDFLAGS)' -o $(OUT)/linux-$$arch/provisioner ./cmd/provisioner || exit 1; \
	done

mips:
	CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat $(GO) build -trimpath -ldflags='$(LDFLAGS)' -o $(OUT)/mips/provisioner ./cmd/provisioner

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

image:
	$(PODMAN) build -t localhost/provisioner -f Containerfile .
