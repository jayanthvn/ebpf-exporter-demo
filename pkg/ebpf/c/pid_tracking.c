#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_NOEXIST 1
#define BPF_F_INDEX_MASK 0xffffffffULL
#define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK

struct data_t {
        __u32 srcaddr;
        __u32 dstaddr;
};

/*
struct bpf_map_def_pvt {
  __u32 map_type;
  __u32 key_size;
  __u32 value_size;
  __u32 max_entries;
  __u32 map_flags;
  // Array/Hash of maps use case: pointer to inner map template
  void *inner_map_def;
  // Define this to make map system wide ("object pinning")
  // path could be anything, like '/sys/fs/bpf/foo'
  // WARN: You must have BPF filesystem mounted on provided location
  const char *persistent_path;
};
*/
#define PIN_GLOBAL_NS 2

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct event {
	u32 pid;
	u32 type;
};



struct bpf_map_def_pvt SEC("maps") events_pid = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};

struct sched_process_fork_t {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char parent_comm[16];
    u32 parent_pid;
    char child_comm[16];
    u32 child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int sched_process_fork(struct sched_process_fork_t *ctx) {
	  struct event ev = {};
	  ev.pid = ctx->child_pid;
	  ev.type = 0;
  	__u64 flags = BPF_F_CURRENT_CPU;
  	bpf_perf_event_output(ctx, &events_pid, flags, &ev, sizeof(ev)); 
    return 0;
}

struct  sched_process_exit_t {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char comm[16];
    u32 pid;
    int prio;
};

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(struct sched_process_exit_t *ctx) {
	  struct event ev = {};
	  ev.pid = ctx->pid;
	  ev.type = 1;
  	__u64 flags = BPF_F_CURRENT_CPU;
  	bpf_perf_event_output(ctx, &events_pid, flags, &ev, sizeof(ev)); 
    return 0;
}


char _license[] SEC("license") = "GPL";