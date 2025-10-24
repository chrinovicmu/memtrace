
# Top-level Makefile for memtrace project

# Directories
SRC_DIR := src
INCLUDE_DIR := include
BPF_OBJ := $(SRC_DIR)/memtrace.bpf.o
BPF_SKEL := $(SRC_DIR)/memtrace.skel.h
USER_SRC := $(SRC_DIR)/run_memtrace.cpp
USER_BIN := run_memtrace

# Tools
CLANG := clang
BPFOBJ := bpftool
CXX := g++
CFLAGS := -I$(INCLUDE_DIR) -O2 -g -Wall
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_x86 -I$(INCLUDE_DIR) -O2 -g -Wall

# Default target
all: $(USER_BIN)

# Build eBPF object file
$(BPF_OBJ): $(SRC_DIR)/memtrace.bpf.c
	@echo "Compiling BPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate skeleton header
$(BPF_SKEL): $(BPF_OBJ)
	@echo "Generating BPF skeleton..."
	$(BPFOBJ) gen skeleton $< > $@

# Build user-space binary

$(USER_BIN): $(USER_SRC) $(BPF_SKEL)
	@echo "Building user-space loader..."
	$(CXX) $(CFLAGS) $< -o $@ -lelf -lz -lbpf

# Clean build artifacts
clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(USER_BIN)

.PHONY: all clean
