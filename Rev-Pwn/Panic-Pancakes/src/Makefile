##
# PANCAKE PANIC — Build system
#
# The Makefile provides targets to build and package the vulnerable
# binary used for the challenge. By default `make` produces a
# non‑stripped binary suitable for local exploitation and debugging.
# The `release` target adds the `-s` flag to strip symbols, producing
# a leaner binary for distribution. The `debug` target adds debug
# information for in‑depth analysis. A `docker` target builds a
# self‑contained Docker image that exposes the service on port 7331.

CC       ?= gcc
CFLAGS   ?= -fno-stack-protector -z execstack -no-pie -O0 -m64 -fcf-protection=none -w
LDFLAGS  ?=

SRC      = pancake_panic.c
BIN      = ../handout/pancake_panic

.PHONY: all debug release clean docker

# Default target: build an unstripped binary. This version retains
# symbols so that tools like Pwntools can automatically locate
# serve_flag().
all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Build a version with debug symbols (-g). This is useful for
# inspecting the binary with GDB and other disassemblers. The output
# binary name is the same so you should `make clean` before switching
# between release and debug builds.
debug: CFLAGS += -g
debug: clean $(BIN)
	@echo "Built debug binary: $(BIN)"

# Build a stripped release binary (-s). The resulting binary has no
# symbol table, making reverse engineering slightly harder but
# preserving the same code addresses thanks to -no-pie. Note: the
# solve script relies on symbols, so keep a non‑stripped copy for
# local exploitation.
release: CFLAGS += -s
release: clean $(BIN)
	@echo "Built stripped release binary: $(BIN)"

# Clean up build artefacts.
clean:
	rm -f $(BIN)

# Build the Docker image. This copies the stripped binary and flag
# into a minimal Ubuntu base image and exposes port 7331. Use
# `docker run -p 7331:7331 pancake-panic` to serve the challenge.
docker: release
	docker build -t pancake-panic -f Dockerfile .
	@echo "Docker image 'pancake-panic' built successfully."
