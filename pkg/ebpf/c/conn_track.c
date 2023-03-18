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
	u8 line[80];
};

struct bpf_map_def_pvt SEC("maps") flow_origin = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct nf_conn *),
  .value_size = sizeof(u64),
  .max_entries = 65535,
  .pinning = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt SEC("maps") events_conn = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};

struct conntrack_cache {
  union nf_inet_addr srcaddr;
  union nf_inet_addr dstaddr;
	__u16 src_port;
	__u16 dst_port;
	__u8 proto;
};

/*
static __always_inline u32 flow_status(struct nf_conn *ct) {
  u32 status;
  bpf_probe_read(&status, sizeof(status), &ct->status);
  return status;
}
*/
/*
static __always_inline void get_conntrack_tuple(struct conntrack_cache *data, struct nf_conn *ct) {

  struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
  bpf_probe_read(&tuplehash, sizeof(tuplehash), &ct->tuplehash);

  bpf_probe_read(&data->proto, sizeof(data->proto), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum);
 
  bpf_probe_read(&data->srcaddr, sizeof(data->srcaddr), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3);
  bpf_probe_read(&data->dstaddr, sizeof(data->dstaddr), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3);

  bpf_probe_read(&data->src_port, sizeof(data->src_port), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all);
  bpf_probe_read(&data->dst_port, sizeof(data->dst_port), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all);
}*/

SEC("kprobe/__nf_conntrack_hash_insert")
int conn_insert(struct pt_regs *ctx) {

/*
  	u64 ts = 20;

  	struct nf_conn *ct = (struct nf_conn *) PT_REGS_PARM1(ctx);

   	if (flow_status(ct) == 0)
   	 	return 0;

  struct data_t evt = {};
  struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
  bpf_probe_read(&tuplehash, sizeof(tuplehash), &ct->tuplehash);

  bpf_probe_read(&evt.srcaddr, sizeof(evt.srcaddr), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3);
  bpf_probe_read(&evt.dstaddr, sizeof(evt.dstaddr), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3); 

	__u64 flags = BPF_F_CURRENT_CPU;
  bpf_perf_event_output(ctx, &events_conn, flags, &evt, sizeof(evt));

	bpf_map_update_elem(&flow_origin, &ct, &ts, BPF_NOEXIST);
  */
  __u32 evt_test = 20;
  __u64 flags = BPF_F_CURRENT_CPU;
  bpf_perf_event_output(ctx, &events_conn, flags, &evt_test, sizeof(evt_test)); 
  //struct event event;
  //event.pid = bpf_get_current_pid_tgid() >> 32;
	//bpf_probe_read(&event.line, sizeof(event.line), (void *)PT_REGS_RC(ctx));

	//bpf_perf_event_output(ctx, &events_conn, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

/*
SEC("kprobe/nf_ct_delete")
int conn_del(struct pt_regs *ctx) {

  struct nf_conn *ct = (struct nf_conn *) PT_REGS_PARM1(ctx);
  //struct conntrack_cache conn_data;
  //get_conntrack_tuple(&conn_data, ct);

  //Use conn_data to compare sport/dport/sip/dip/proto

  struct data_t evt = {};
  struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
  bpf_probe_read(&tuplehash, sizeof(tuplehash), &ct->tuplehash);

  bpf_probe_read(&evt.srcaddr, sizeof(evt.srcaddr), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3);
  bpf_probe_read(&evt.dstaddr, sizeof(evt.dstaddr), &tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3); 

	__u64 flags = BPF_F_CURRENT_CPU;
  bpf_perf_event_output(ctx, &events_conn, flags, &evt, sizeof(evt)); 
  bpf_map_delete_elem(&flow_origin, &ct);

  return 0;
}
*/

char _license[] SEC("license") = "GPL";

