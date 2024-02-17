#ifndef __COMMON_H
#define __COMMON_H

#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct event
{
    __u64 timestamp_ns; //  = bpf_ktime_get_ns()
    struct iphdr ip_info;
    struct tcphdr tcp_info;
};

#endif