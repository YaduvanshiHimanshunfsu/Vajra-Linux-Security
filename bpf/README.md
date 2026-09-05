# eBPF sensor

The production sensor uses CO-RE eBPF programs compiled against target BTF metadata.
The agent checks kernel features before loading the programs and falls back to a
non-enforcing audit source when eBPF is unavailable.

## Build prerequisites on the Linux target

- `clang`, `llvm`, `libbpf-dev`, `bpftool`, and Linux headers
- `/sys/kernel/btf/vmlinux` for CO-RE BTF information
- root or precisely scoped capabilities for program loading

Generate the target-specific `vmlinux.h` with `make vmlinux.h`, then build with
`make`. Generated headers and object files are deliberately ignored by Git.
