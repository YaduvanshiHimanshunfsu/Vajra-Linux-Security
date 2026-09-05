# Aegis agent

The agent owns Linux host collection and must not make detection or containment
decisions. It produces evidence with a stable host/boot/process identity.

Current command for a Linux host:

```bash
cargo run --manifest-path agent/Cargo.toml -- --simulate
```

The first implementation validates host capabilities and reports BTF/PSI support.
The next increment attaches `bpf/process_trace.bpf.o`, consumes ring-buffer records,
then publishes versioned events to Redpanda over mTLS.
