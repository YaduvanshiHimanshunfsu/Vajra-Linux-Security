#ifndef AEGIS_EVENTS_H
#define AEGIS_EVENTS_H

#if !defined(__bpf__) && !defined(__VMLINUX_H__)
#include <linux/types.h>
#endif

#define AEGIS_COMM_LEN 16
#define AEGIS_PATH_LEN 256

enum aegis_event_type {
    AEGIS_PROCESS_EXEC = 1,
    AEGIS_PROCESS_EXIT = 2,
    AEGIS_FILE_OPEN    = 3,
    AEGIS_NET_CONNECT  = 4,
};

/*
 * Fixed-size records deliberately keep kernel work bounded. User space enriches
 * paths, hashes, container identity, and command-line data after ring-buffer read.
 */
struct aegis_process_event {
    __u64 monotonic_ns;
    __u64 process_start_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 event_type;
    char comm[AEGIS_COMM_LEN];
    char filename[AEGIS_PATH_LEN];
};

struct aegis_file_event {
    __u64 monotonic_ns;
    __u32 pid;
    __u32 uid;
    __u32 event_type;
    __u32 flags;
    char comm[AEGIS_COMM_LEN];
    char filename[AEGIS_PATH_LEN];
};

struct aegis_net_event {
    __u64 monotonic_ns;
    __u32 pid;
    __u32 uid;
    __u32 event_type;
    __u32 daddr;        /* IPv4 destination in network byte order */
    __u16 dport;        /* Destination port */
    __u16 proto;        /* Protocol (IPPROTO_TCP) */
    char comm[AEGIS_COMM_LEN];
};

#endif
