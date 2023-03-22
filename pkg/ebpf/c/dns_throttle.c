#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_F_INDEX_MASK 0xffffffffULL
#define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct bpf_map_def_pvt SEC("maps") dns_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};

struct event{
	__u32 ingress_ifindex;
};

#define GET_ADDRESS(buffer, member)  (void*) (((char*)buffer) + offsetof(typeof(*buffer), member))

SEC("tc_cls")
int handle_egress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
  	
    struct ethhdr *ether = data;
    if (data + sizeof(*ether) > data_end) {
    	return BPF_OK;
    }

    struct event evt = {};
    evt.ingress_ifindex = skb->ingress_ifindex;
    //bpf_probe_read(&evt.ingress_ifindex, sizeof(skb->ingress_ifindex), &skb->ingress_ifindex);
  	
    if (ether->h_proto == 0x08U) {  // htons(ETH_P_IP) -> 0x08U
    		data += sizeof(*ether);
    		struct iphdr *ip = data;
    		struct udphdr *l4hdr = data + sizeof(struct iphdr);
    		if (data + sizeof(*ip) > data_end) {
      		    return BPF_OK;
    		}
    		if (ip->version != 4) {
      		    return BPF_OK;
    		}
    		if (data + sizeof(*ip) + sizeof(*l4hdr) > data_end) {
    	 	   return BPF_OK;
    		}

		/*
		if (ip->protocol == IPPROTO_TCP) {
		    struct tcphdr *l4hdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
		    l4port = l4hdr->source;
		    bpf_printk("L4 Port: %d", l4port);
		} else if (ip->protocol == IPPROTO_UDP) {
		    struct udphdr *l4hdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
		    l4port = l4hdr->source;
		}
		*/

		if ((((ip->daddr >> 24) & 0xff) == 2) || (((ip->daddr >> 24) & 0xff) == 253)) {
			__u64 flags = BPF_F_CURRENT_CPU;
  			bpf_perf_event_output(skb, &dns_events, flags, &evt, sizeof(evt)); 
		}
    	}
	return BPF_OK;
}

char _license[] SEC("license") = "GPL";