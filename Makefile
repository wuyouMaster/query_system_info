# Project name
PROJECT_NAME = query_system_info

# Output directory
DIST_DIR = dist

# Platform to target mapping
# Usage: make build PLATFORM=linux-x64
ifeq ($(PLATFORM),linux-x64)
    TARGET = x86_64-unknown-linux-gnu
    OUTPUT_NAME = $(PROJECT_NAME)-linux-x64
    EXT =
else ifeq ($(PLATFORM),linux-arm64)
    TARGET = aarch64-unknown-linux-gnu
    OUTPUT_NAME = $(PROJECT_NAME)-linux-arm64
    EXT =
else ifeq ($(PLATFORM),windows-x64)
    TARGET = x86_64-pc-windows-gnu
    OUTPUT_NAME = $(PROJECT_NAME)-windows-x64
    EXT = .exe
else ifeq ($(PLATFORM),macos-x64)
    TARGET = x86_64-apple-darwin
    OUTPUT_NAME = $(PROJECT_NAME)-macos-x64
    EXT =
else ifeq ($(PLATFORM),macos-arm64)
    TARGET = aarch64-apple-darwin
    OUTPUT_NAME = $(PROJECT_NAME)-macos-arm64
    EXT =
else
    # Default: build for current platform
    TARGET =
    OUTPUT_NAME = $(PROJECT_NAME)
    EXT =
endif

# Default target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  make build              - Build for current platform"
	@echo "  make build PLATFORM=... - Build for specific platform"
	@echo "  make all                - Build for all platforms"
	@echo "  make clean              - Clean build artifacts"
	@echo "  make run                - Run the project"
	@echo "  make example            - Run basic_usage example"
	@echo ""
	@echo "Available platforms:"
	@echo "  linux-x64      - Linux x86_64"
	@echo "  linux-arm64    - Linux ARM64"
	@echo "  windows-x64    - Windows x86_64"
	@echo "  macos-x64      - macOS x86_64 (Intel)"
	@echo "  macos-arm64    - macOS ARM64 (Apple Silicon)"
	@echo ""
	@echo "Examples:"
	@echo "  make build PLATFORM=linux-x64"
	@echo "  make build PLATFORM=windows-x64"

# Build for current or specified platform
.PHONY: build
build:
	@mkdir -p $(DIST_DIR)
	@echo "Building for $(if $(PLATFORM),$(PLATFORM),current platform)..."
ifeq ($(TARGET),)
	cargo build --release
	cp target/release/$(PROJECT_NAME) $(DIST_DIR)/$(OUTPUT_NAME)
else
	cargo build --release --target=$(TARGET)
	cp target/$(TARGET)/release/$(PROJECT_NAME)$(EXT) $(DIST_DIR)/$(OUTPUT_NAME)$(EXT)
endif
	@echo "Build complete: $(DIST_DIR)/$(OUTPUT_NAME)$(EXT)"

# Build for all platforms
.PHONY: all
all:
	@echo "Building for all platforms..."
	@$(MAKE) build PLATFORM=linux-x64
	@$(MAKE) build PLATFORM=linux-arm64
	@$(MAKE) build PLATFORM=windows-x64
	@$(MAKE) build PLATFORM=macos-x64
	@$(MAKE) build PLATFORM=macos-arm64
	@echo "All builds complete!"

# Individual platform targets
.PHONY: linux-x64 linux-arm64 windows-x64 macos-x64 macos-arm64
linux-x64:
	@$(MAKE) build PLATFORM=linux-x64

linux-arm64:
	@$(MAKE) build PLATFORM=linux-arm64

windows-x64:
	@$(MAKE) build PLATFORM=windows-x64

macos-x64:
	@$(MAKE) build PLATFORM=macos-x64

macos-arm64:
	@$(MAKE) build PLATFORM=macos-arm64

# Run the project
.PHONY: run
run:
	cargo run

# Run example
.PHONY: example
example:
	cargo run --example basic_usage

# Clean build artifacts
.PHONY: clean
clean:
	cargo clean
	rm -rf $(DIST_DIR)
	@echo "Clean complete!"

# Install required targets
.PHONY: install-targets
install-targets:
	@echo "Installing cross-compilation targets..."
	rustup target add x86_64-unknown-linux-gnu
	rustup target add aarch64-unknown-linux-gnu
	rustup target add x86_64-pc-windows-gnu
	rustup target add x86_64-apple-darwin
	rustup target add aarch64-apple-darwin
	@echo "Targets installed!"

# Check project
.PHONY: check
check:
	cargo check

# Run tests
.PHONY: test
test:
	cargo test

# Legacy target (for backward compatibility)
.PHONY: cross-build
cross-build: all