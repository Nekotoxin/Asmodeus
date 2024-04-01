#ifndef __COMMON_H
#define __COMMON_H

#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct event {
    __u64 timestamp_ns; // = bpf_ktime_get_ns()
    struct iphdr ip_info;
    int protocol;
    union {
        struct tcphdr tcp_info;
        struct udphdr udp_info;
    } transport_info;
    __u64 padding;
};

#endif