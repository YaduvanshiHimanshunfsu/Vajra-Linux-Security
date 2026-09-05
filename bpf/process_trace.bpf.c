#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "aegis_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} process_events SEC(".maps");

/* 
 * Tracepoint: Process Execution Lifecycle
 * Captures process execve/execveat with binary dentry path resolution via CO-RE
 */
SEC("tracepoint/sched/sched_process_exec")
int observe_process_exec(void *ctx)
{
    struct aegis_process_event *event;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->monotonic_ns = bpf_ktime_get_ns();
    event->process_start_ns = BPF_CORE_READ(task, start_boottime);
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->uid = bpf_get_current_uid_gid();
    event->event_type = AEGIS_PROCESS_EXEC;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    /* Extract binary dentry name from task memory descriptor using CO-RE */
    struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
    if (exe_file) {
        struct qstr d_name = BPF_CORE_READ(exe_file, f_path.dentry, d_name);
        bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), d_name.name);
    } else {
        bpf_get_current_comm(event->filename, sizeof(event->filename));
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
 * Tracepoint: File Open Activity
 * Captures openat syscalls for Living-off-the-Land (LotL) and decoy credential access
 */
struct sys_enter_openat_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int dfd;
    const char *filename;
    int flags;
    unsigned short mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int observe_file_open(struct sys_enter_openat_args *ctx)
{
    struct aegis_file_event *event;

    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->monotonic_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    event->event_type = AEGIS_FILE_OPEN;
    event->flags = ctx->flags;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), ctx->filename);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
 * Kprobe: Outbound Network Connections
 * Tracks TCP egress socket destinations for C2 beaconing and exfiltration detection
 */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(observe_tcp_connect, struct sock *sk)
{
    struct aegis_net_event *event;

    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->monotonic_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    event->event_type = AEGIS_NET_CONNECT;
    event->proto = 6; /* IPPROTO_TCP */
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&event->dport, sk, __sk_common.skc_dport);

    bpf_ringbuf_submit(event, 0);
    return 0;
}
