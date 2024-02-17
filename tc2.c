// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <argp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/libbpf.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include "tc2.h"
#include "tc2.skel.h"

void handle_sigint(int sig)
{
    printf("Terminating\n");
    exit(0);
}

int handle_event(void *ctx, void *data, size_t len)
{
    struct event *e = (struct event *)data;

    // Print timestamp
    printf("Packet Transmit: %s:%u -> ", inet_ntoa(*(struct in_addr *)&e->ip_info.saddr), ntohs(e->tcp_info.source));
    printf("%s:%u\n\n", inet_ntoa(*(struct in_addr *)&e->ip_info.daddr), ntohs(e->tcp_info.dest));

    printf("Timestamp: %llu\n\n", e->timestamp_ns);

    // Print IP header
    printf("IP Header:\n");
    printf("  Version: %u\n", e->ip_info.version);
    printf("  Header Length: %u bytes\n", e->ip_info.ihl * 4);
    printf("  Total Length: %u bytes\n", ntohs(e->ip_info.tot_len));
    printf("  Protocol: %u\n", e->ip_info.protocol);
    printf("  Source IP: %s\n", inet_ntoa(*(struct in_addr *)&e->ip_info.saddr));
    printf("  Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&e->ip_info.daddr));

    // Print TCP header
    printf("TCP Header:\n");
    printf("  Source Port: %u\n", ntohs(e->tcp_info.source));
    printf("  Destination Port: %u\n", ntohs(e->tcp_info.dest));
    printf("  Sequence Number: %u\n", ntohl(e->tcp_info.seq));
    printf("  Acknowledgment Number: %u\n", ntohl(e->tcp_info.ack_seq));
    printf("  Data Offset: %u bytes\n", e->tcp_info.doff * 4);
    printf("  Window Size: %u\n", ntohs(e->tcp_info.window));
    printf("  Checksum: 0x%x\n", ntohs(e->tcp_info.check));
    printf("  Urgent Pointer: %u\n", ntohs(e->tcp_info.urg_ptr));

    // Print a separator
    printf("----------------------------------------------------------\n");
    
    return 0;
}

int main(int argc, char *argv[])
{
    unsigned int ifindex;

    if (argc != 2)
    {
        printf("Provide interface name\n");
    }

    ifindex = if_nametoindex(argv[1]);

    signal(SIGINT, handle_sigint);

    struct tc2_bpf *skel = tc2_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    LIBBPF_OPTS(bpf_tcx_opts, optl);
    struct bpf_link *link0 = bpf_program__attach_tcx(skel->progs.tc_ingress, ifindex, &optl);
    if (!link0)
    {
        fprintf(stderr, "bpf_program__attach_tcx\n");
        return 1;
    }
    struct bpf_link *link1 = bpf_program__attach_tcx(skel->progs.tc_egress, ifindex, &optl);
    if (!link1)
    {
        fprintf(stderr, "bpf_program__attach_tcx\n");
        return 1;
    }

    struct bpf_map *ringbuf_map = bpf_object__find_map_by_name(skel->obj, "my_map");
    if (!ringbuf_map)
    {
        fprintf(stderr, "Failed to get ring buffer map\n");
        return 1;
    }

    struct ring_buffer *ringbuf = ring_buffer__new(bpf_map__fd(ringbuf_map), handle_event, NULL, NULL);
    if (!ringbuf)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Successfully started! Please Ctrl+C to stop.\n");
    printf("\033[1;31m");
    printf("Source IP, Destination IP, Source Port, Destination Port, SIN, FIN, RST, PSH, ACK \n");
    printf("\033[0m");
    while (1)
    {
        if (ring_buffer__poll(ringbuf, 1000) < 0)
        {
            fprintf(stderr, "Error polling ring buffer\n");
            break;
        }
    }

    return 0;
}