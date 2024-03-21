#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "tc2.h"

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

#define INGRESS 1
#define EGRESS -1

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} my_map SEC(".maps");

static int packet_stat(struct __sk_buff *ctx, int direction) {
    struct event *e;

    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *eth_header = data;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    if (ctx->protocol != bpf_htons(ETH_P_IP) || (void *)(eth_header + 1) > data_end)
        return TC_ACT_OK;

    ip_header = (struct iphdr *)(eth_header + 1);
    if ((void *)(ip_header + 1) > data_end)
        return TC_ACT_OK;

    // Reserve space for event in BPF ring buffer
    e = bpf_ringbuf_reserve(&my_map, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;

    // Fill the event structure
    e->timestamp_ns = bpf_ktime_get_ns();
    __builtin_memcpy(&e->ip_info, ip_header, sizeof(struct iphdr));

    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = (struct tcphdr *)(ip_header + 1);
        if ((void *)(tcp_header + 1) > data_end) {
            bpf_ringbuf_discard(e, 0);
            return TC_ACT_OK;
        }
        e->protocol = 6;
        __builtin_memcpy(&e->transport_info.tcp_info, tcp_header, sizeof(struct tcphdr));
    } else if (ip_header->protocol == IPPROTO_UDP) {
        udp_header = (struct udphdr *)(ip_header + 1);
        if ((void *)(udp_header + 1) > data_end) {
            bpf_ringbuf_discard(e, 0);
            return TC_ACT_OK;
        }
        e->protocol = 17;
        __builtin_memcpy(&e->transport_info.udp_info, udp_header, sizeof(struct udphdr));
    } else {
        bpf_ringbuf_discard(e, 0);
        return TC_ACT_OK;
    }
    bpf_ringbuf_submit(e, 0);

    return TC_ACT_OK;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *ctx) {
    return packet_stat(ctx, INGRESS);
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *ctx) {
    return packet_stat(ctx, EGRESS);
}


