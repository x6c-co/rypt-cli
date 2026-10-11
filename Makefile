BINARY    := rypt
PKG       := ./cmd/rypt
DIST      := dist
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

GO        ?= go
# EXE is .exe when building for Windows, so that "make build" there gives a
# runnable rypt.exe. Recursive, so go env runs only when it is used.
EXE        = $(shell $(GO) env GOEXE)
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)
SHA256SUM := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo shasum -a 256)

export CGO_ENABLED := 0

.PHONY: all build test race vet integration dist clean

all: vet test build

# build compiles rypt for this machine.
build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)$(EXE) $(PKG)

test:
	$(GO) test ./...

# race needs cgo.
race:
	CGO_ENABLED=1 $(GO) test -race ./...

# vet also covers the integration tests and scripts/probe.go, which ./...
# skips because of their build tags. gofmt's errors count as output.
vet:
	$(GO) vet ./...
	$(GO) vet -tags integration ./integration/...
	$(GO) vet scripts/probe.go
	@out="$$("$$($(GO) env GOROOT)/bin/gofmt" -l . 2>&1)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

# integration runs against the live API. It needs RYPT_TOKEN and RYPT_KEY_ID
# in the environment and spends a few operations on that key.
integration:
	$(GO) test -tags integration -count=1 -v ./integration/...

# dist cross-compiles rypt for every platform and writes SHA256SUMS.
dist:
	@rm -rf $(DIST) && mkdir -p $(DIST)
	@set -e; for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; \
		if [ "$$os" = windows ]; then ext=.exe; fi; \
		out=$(DIST)/$(BINARY)-$$os-$$arch$$ext; \
		echo "$$out"; \
		GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $$out $(PKG); \
	done
	cd $(DIST) && $(SHA256SUM) $(BINARY)-* > SHA256SUMS
	@cat $(DIST)/SHA256SUMS

clean:
	rm -rf $(DIST) $(BINARY) $(BINARY).exe
