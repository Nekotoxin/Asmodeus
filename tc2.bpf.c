// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/socket.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "tc2.h"

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} my_map SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static int packet_stat(struct __sk_buff *ctx){
    struct event *e;

    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    eth_header = data;
    if ((void *)(eth_header + 1) > data_end)
        return TC_ACT_OK;

    ip_header = (struct iphdr *)(eth_header + 1);
    if ((void *)(ip_header + 1) > data_end)
        return TC_ACT_OK;

    if (ip_header->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    tcp_header = (struct tcphdr *)(ip_header + 1);
    if ((void *)(tcp_header + 1) > data_end)
        return TC_ACT_OK;

    // Reserve space for event in BPF ring buffer
    e = bpf_ringbuf_reserve(&my_map, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;

    // Fill the event structure
    e->timestamp_ns = bpf_ktime_get_ns();
    __builtin_memcpy(&e->ip_info, ip_header, sizeof(struct iphdr));
    __builtin_memcpy(&e->tcp_info, tcp_header, sizeof(struct tcphdr));

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(e, 0);
    
    return TC_ACT_OK;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *ctx) {
    return packet_stat(ctx);
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *ctx) {
    return packet_stat(ctx);
}



char _license[] SEC("license") = "GPL";
