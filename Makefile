APP_NAME := vocsign
VERSION := 0.1.0
OUTPUT_DIR := build
PKG := ./cmd/vocsign

GO ?= go
DOCKER ?= docker

# For Linux desktop Gio builds we keep cgo enabled.
CGO_LINUX ?= 1
# Windows certificate discovery requires cgo (system store + NSS).
CGO_WINDOWS ?= 1
# macOS cross-build requires cgo + Darwin cross compiler toolchain.
CGO_DARWIN ?= 1
MACOSX_DEPLOYMENT_TARGET_AMD64 ?= 11.0
MACOSX_DEPLOYMENT_TARGET_ARM64 ?= 11.0

LD_FLAGS_COMMON := -s -w
WIN_GUI_FLAGS := -H=windowsgui
GO_BUILD_FLAGS := -buildvcs=false

# Optional local cross compilers (when not using Docker).
CC_WINDOWS ?= x86_64-w64-mingw32-gcc
CC_DARWIN_AMD64 ?= o64-clang
CC_DARWIN_ARM64 ?= oa64-clang

# Docker image with cross toolchains (mingw + osxcross).
DOCKER_CROSS_IMAGE ?= ghcr.io/goreleaser/goreleaser-cross:v1.25.7

.PHONY: help all clean test verify prepare-output build-host \
	build-linux-amd64 build-windows-amd64 build-darwin-amd64 build-darwin-arm64 \
	release release-local release-docker release-inside-docker \
	release-docker-core release-docker-macos release-inside-docker-core release-inside-docker-macos

help:
	@echo "Targets:"
	@echo "  make build-host        - Build binary for current host platform"
	@echo "  make release-local     - Build Linux/Windows/macOS binaries using local toolchains"
	@echo "  make release-docker    - Build Linux+Windows in Docker; macOS locally (or via release-docker-macos)"
	@echo "  make release-docker-core - Build Linux+Windows in Docker"
	@echo "  make release-docker-macos - Build macOS in Docker (requires image with osxcross toolchain)"
	@echo "  make release           - Alias to release-docker"
	@echo "  make test              - Run tests"
	@echo "  make verify            - Run tests + host build"
	@echo "  make clean             - Remove build artifacts"

all: build-host

prepare-output:
	@if [ -d "$(OUTPUT_DIR)" ] && [ ! -w "$(OUTPUT_DIR)" ]; then \
		backup="$(OUTPUT_DIR).stale.$$(date +%Y%m%d%H%M%S)"; \
		echo "Output directory '$(OUTPUT_DIR)' is not writable; moving it to '$$backup'"; \
		mv "$(OUTPUT_DIR)" "$$backup"; \
	fi
	@mkdir -p "$(OUTPUT_DIR)"

test:
	$(GO) test ./...

verify: test build-host

build-host: prepare-output
	CGO_ENABLED=1 $(GO) build $(GO_BUILD_FLAGS) -trimpath -ldflags "$(LD_FLAGS_COMMON)" -o $(OUTPUT_DIR)/$(APP_NAME)-$$(go env GOOS)-$$(go env GOARCH) $(PKG)

build-linux-amd64: prepare-output
	GOOS=linux GOARCH=amd64 CGO_ENABLED=$(CGO_LINUX) $(GO) build $(GO_BUILD_FLAGS) -trimpath -ldflags "$(LD_FLAGS_COMMON)" -o $(OUTPUT_DIR)/$(APP_NAME)-linux-amd64 $(PKG)

build-windows-amd64: prepare-output
	GOOS=windows GOARCH=amd64 CGO_ENABLED=$(CGO_WINDOWS) CC=$(CC_WINDOWS) $(GO) build $(GO_BUILD_FLAGS) -trimpath -ldflags "$(LD_FLAGS_COMMON) $(WIN_GUI_FLAGS)" -o $(OUTPUT_DIR)/$(APP_NAME)-windows-amd64.exe $(PKG)

build-darwin-amd64: prepare-output
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=$(CGO_DARWIN) CC=$(CC_DARWIN_AMD64) MACOSX_DEPLOYMENT_TARGET=$(MACOSX_DEPLOYMENT_TARGET_AMD64) $(GO) build $(GO_BUILD_FLAGS) -trimpath -ldflags "$(LD_FLAGS_COMMON)" -o $(OUTPUT_DIR)/$(APP_NAME)-darwin-amd64 $(PKG)

build-darwin-arm64: prepare-output
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=$(CGO_DARWIN) CC=$(CC_DARWIN_ARM64) MACOSX_DEPLOYMENT_TARGET=$(MACOSX_DEPLOYMENT_TARGET_ARM64) $(GO) build $(GO_BUILD_FLAGS) -trimpath -ldflags "$(LD_FLAGS_COMMON)" -o $(OUTPUT_DIR)/$(APP_NAME)-darwin-arm64 $(PKG)

release-local: build-linux-amd64 build-windows-amd64 build-darwin-amd64 build-darwin-arm64

# Recommended: cross-build core artifacts with Docker to avoid host toolchain drift.
# Note: current goreleaser-cross image does not provide Darwin compilers.
release-docker:
	$(DOCKER) run --rm --entrypoint /bin/sh -v "$(PWD):/src" -w /src $(DOCKER_CROSS_IMAGE) -lc "export PATH=/usr/local/go/bin:$$PATH && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends pkg-config libx11-dev libxkbcommon-dev libxkbcommon-x11-dev libx11-xcb-dev libxcursor-dev libxfixes-dev libwayland-dev libegl1-mesa-dev libgles2-mesa-dev libvulkan-dev && make release-inside-docker-core"
	$(MAKE) release-docker-macos

release-docker-core:
	$(DOCKER) run --rm --entrypoint /bin/sh -v "$(PWD):/src" -w /src $(DOCKER_CROSS_IMAGE) -lc "export PATH=/usr/local/go/bin:$$PATH && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends pkg-config libx11-dev libxkbcommon-dev libxkbcommon-x11-dev libx11-xcb-dev libxcursor-dev libxfixes-dev libwayland-dev libegl1-mesa-dev libgles2-mesa-dev libvulkan-dev && make release-inside-docker-core"

# Optional macOS docker build; requires osxcross-compatible image/toolchain.
release-docker-macos:
	$(DOCKER) run --rm --entrypoint /bin/sh -v "$(PWD):/src" -w /src $(DOCKER_CROSS_IMAGE) -lc "export PATH=/usr/local/osxcross/bin:/usr/local/go/bin:$$PATH && go mod download && find /root/go/pkg/mod -type f -path '*/gioui.org/x@*/explorer/*' -exec sed -i 's#<Appkit/AppKit.h>#<AppKit/AppKit.h>#' {} + && find /root/go/pkg/mod -type f \( -path '*/gioui.org/x@*/explorer/*.go' -o -path '*/gioui.org/x@*/notify/macos/*.go' \) -exec sed -i 's# -fmodules##g' {} + && find /root/go/pkg/mod -type f -path '*/gioui.org/x@*/explorer/explorer_macos.go' -exec sed -i '/#cgo CFLAGS:/a #cgo LDFLAGS: -framework UniformTypeIdentifiers' {} + && make release-inside-docker-macos"

release-inside-docker-core: clean build-linux-amd64 build-windows-amd64

release-inside-docker-macos: build-darwin-amd64 build-darwin-arm64

release: release-docker

clean:
	rm -rf $(OUTPUT_DIR)
	$(GO) clean
