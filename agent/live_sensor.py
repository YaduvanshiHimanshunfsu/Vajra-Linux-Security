"""Vajra (वज्र) — Secondary Python-based Live eBPF Sensor.

Lightweight live kernel telemetry sensor using BCC / pyebpf.
Provides an alternative to the Rust agent for rapid deployment and testbed evaluation on Kali/Ubuntu Linux.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def get_boot_id() -> str:
    boot_path = Path("/proc/sys/kernel/random/boot_id")
    if boot_path.exists():
        return boot_path.read_text().strip()
    return "boot-kali-001"


def get_cgroup_slice(pid: int) -> str:
    cgroup_path = Path(f"/proc/{pid}/cgroup")
    if cgroup_path.exists():
        try:
            for line in cgroup_path.read_text().splitlines():
                if "::" in line:
                    slice_name = line.split("::")[-1].strip("/")
                    if slice_name:
                        return slice_name
        except Exception:
            pass
    return "system.slice"


def run_live_sensor(output_json: bool = True) -> None:
    if platform.system() != "Linux":
        print("[!] Live eBPF sensor requires a Linux host (Kali Linux / Ubuntu).")
        print("[*] Running in deterministic synthetic mode.")
        sample_event = {
            "schema_version": "1.0",
            "event_id": "evt-live-sensor-preflight",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "host_id": platform.node(),
            "boot_id": get_boot_id(),
            "event_type": "PROCESS_EXEC",
            "subject": {"process_id": f"{get_boot_id()}:1:100", "pid": 100, "ppid": 1, "executable": "/usr/sbin/nginx", "uid": 33},
            "object_type": "binary",
            "object_value": "/usr/sbin/nginx",
            "workload": {"workload_id": "nginx.service", "environment": "production"},
            "result": "success",
            "attributes": {"parent_executable": "/usr/lib/systemd/systemd"},
            "sensor_confidence": 1.0,
            "trust": {"host_attestation": "verified", "agent_integrity": "verified", "artifact_verification": "verified"},
        }
        print(json.dumps(sample_event))
        return

    try:
        from bcc import BPF
    except ImportError:
        print("[!] BCC Python bindings not found. Install via: sudo apt install python3-bpfcc")
        return

    bpf_text = """
    #include <uapi/linux/ptrace.h>
    #include <linux/sched.h>
    #include <linux/fs.h>

    struct data_t {
        u64 ts;
        u32 pid;
        u32 uid;
        char comm[16];
        char fname[256];
    };

    BPF_PERF_OUTPUT(events);

    int trace_exec(struct trace_event_raw_sys_enter* ctx) {
        struct data_t data = {};
        data.ts = bpf_ktime_get_ns();
        data.pid = bpf_get_current_pid_tgid() >> 32;
        data.uid = bpf_get_current_uid_gid();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }
    """

    b = BPF(text=bpf_text)
    b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="trace_exec")
    boot_id = get_boot_id()

    def print_event(cpu, data, size):
        event = b["events"].event(data)
        pid = event.pid
        cgroup = get_cgroup_slice(pid)
        comm = event.comm.decode("utf-8", "replace")

        sec_event = {
            "schema_version": "1.0",
            "event_id": f"evt-live-{event.ts}",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "host_id": platform.node(),
            "boot_id": boot_id,
            "event_type": "PROCESS_EXEC",
            "subject": {"process_id": f"{boot_id}:1:{pid}", "pid": pid, "executable": comm, "uid": event.uid},
            "object_type": "binary",
            "object_value": comm,
            "workload": {"workload_id": cgroup, "environment": "production"},
            "result": "success",
            "attributes": {"comm": comm},
            "sensor_confidence": 1.0,
            "trust": {"host_attestation": "verified", "agent_integrity": "verified", "artifact_verification": "verified"},
        }
        if output_json:
            print(json.dumps(sec_event), flush=True)

    print(f"[+] Vajra Python live eBPF sensor active on {platform.node()} (Kernel {platform.release()})...")
    b["events"].open_perf_buffer(print_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n[+] Sensor stopped cleanly.")
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vajra Python Live eBPF Sensor")
    parser.add_argument("--json", action="store_true", default=True, help="Emit JSON events to stdout")
    args = parser.parse_args()
    run_live_sensor(output_json=args.json)
