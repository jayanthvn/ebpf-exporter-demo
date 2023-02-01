#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_RULES   16
#define BPF_F_NO_PREALLOC 1
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

struct bpf_map_def_pvt SEC("maps") egressifindex = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 10,
        .pinning = PIN_GLOBAL_NS,
};

struct lpm_trie_key {
	__u32	prefixlen;
	__u32	ip;
};

struct lpm_trie_val {
  __u32 protocol;
  __u32 start_port;
  __u32 end_port;
};

struct bpf_map_def_pvt SEC("maps") ingressmap = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_trie_key),
    .value_size = sizeof(struct lpm_trie_val),
    .max_entries = 100,
    .map_flags = BPF_F_NO_PREALLOC,
    .pinning = PIN_GLOBAL_NS,
};

// XDP program //
SEC("xdp")
int firewall(struct xdp_md *ctx) {
  return XDP_DROP;
}

/*
SEC("tc_cls")
int tc_ingress(struct __sk_buff *skb) {
	return BPF_OK;
}

SEC("tc_cls")
int tc_egress(struct __sk_buff *skb) {
	return BPF_OK;
}
*/
char _license[] SEC("license") = "GPL";
