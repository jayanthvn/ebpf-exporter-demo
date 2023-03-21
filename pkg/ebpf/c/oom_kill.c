#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define BPF_F_INDEX_MASK 0xffffffffULL
#define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK
typedef unsigned long args_t;

struct data_t {
        __u32 fpid;
        __u32 tpid;
        char fcomm[TASK_COMM_LEN];
        char tcomm[TASK_COMM_LEN];
};

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
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

struct bpf_map_def_pvt SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct data_t),
    .max_entries = 1024,
};

#define GET_ADDRESS(buffer, member)  (void*) (((char*)buffer) + offsetof(typeof(*buffer), member))

SEC("kprobe/oom_kill_process")
int oom_kill(struct pt_regs *ctx) {
	struct data_t evt = {};
	struct oom_control *oc = (struct oom_control *)PT_REGS_PARM1(ctx);
	evt.fpid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&evt.fcomm, TASK_COMM_LEN);
	
	struct task_struct *p;
        bpf_probe_read(&p, sizeof(p), &oc->chosen);
	bpf_probe_read(&evt.tpid, sizeof(evt.tpid), &p->pid);
	bpf_probe_read(&evt.tcomm, sizeof(evt.tcomm), &p->comm);
	
	__u64 flags = BPF_F_CURRENT_CPU;
        bpf_perf_event_output(ctx, &events, flags, &evt, sizeof(evt));
	return 0;
}

/*
SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *message)
{
        struct data_t *e;

        e = bpf_ringbuf_reserve(&oomkills, sizeof(struct data_t), 0);
        if (!e) {
                return 0;
        }

        e->tpid = BPF_CORE_READ(oc, chosen, tgid);
        bpf_get_current_comm(&e->fcomm, TASK_COMM_LEN);

        e->fpid = bpf_get_current_pid_tgid() >> 32;
        e->pages = BPF_CORE_READ(oc, totalpages);
        bpf_probe_read_kernel(&e->tcomm, sizeof(e->tcomm), BPF_CORE_READ(oc, chosen, comm));

        bpf_ringbuf_submit(e, 0);

        return 0;
}
*/
char _license[] SEC("license") = "GPL";
