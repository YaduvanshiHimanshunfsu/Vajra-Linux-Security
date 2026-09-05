ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I.

all: process_trace.bpf.o

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

process_trace.bpf.o: process_trace.bpf.c aegis_events.h vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f process_trace.bpf.o vmlinux.h
