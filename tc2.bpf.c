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

#define TIME_LEAP 100000000ULL // 每0.1s触发一次用户侧信号，

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64); // 用于存储上次发送通知的时间
	__uint(max_entries, 1);
} last_notify_time_map SEC(".maps");


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

    __u32 key = 0;
    int flags = BPF_RB_NO_WAKEUP; // 默认标志
    __u64 *last_notify_time, current_time_ns;
    // 获取当前时间
    current_time_ns = bpf_ktime_get_ns();

    // 从BPF_MAP_TYPE_ARRAY中获取上次发送通知的时间
    last_notify_time = bpf_map_lookup_elem(&last_notify_time_map, &key);
    if (last_notify_time && current_time_ns - *last_notify_time >= TIME_LEAP) {
        // 如果已经超过了1秒，则使用不同的标志（例如，强制发送通知）
        flags = BPF_RB_FORCE_WAKEUP;

        // 更新上次发送通知的时间
        bpf_map_update_elem(&last_notify_time_map, &key, &current_time_ns, BPF_ANY);
    }

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
    bpf_ringbuf_submit(e, flags); // 使用决定好的flags提交

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


