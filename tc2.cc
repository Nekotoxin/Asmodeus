#include <arpa/inet.h>
#include <net/if.h>
// #include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include "tc2.h"
#include <sys/time.h>
#include <sys/ioctl.h>
#include "tc2.skel.h"
#include <pthread.h>
#include <unistd.h>
#include <algorithm>

#include <unordered_map>
#include <unordered_set>
#include <iostream>

#include "FlowGenerator.h"
FlowGenerator flow_mgr(true, 120000000ULL, 5000000ULL);
IdGenerator packet_id_generator;

__u32 interface_ip;

unsigned int get_interface_ip(char* if_name);
void handle_sigint(int sig);

int handle_event(void *ctx, void *data, size_t len)
{
    if (len < sizeof(struct event)) {
        // 数据长度不足，无法处理
        return 0;
    }

    struct event *e = (struct event *)data;
    
    // 提取源 IP 和目标 IP 地址
    std::vector<uint8_t> src_ip(4), dst_ip(4);
    for (int i = 0; i < 4; ++i) {
        src_ip[i] = (e->ip_info.saddr >> (i * 8)) & 0xFF;
        dst_ip[i] = (e->ip_info.daddr >> (i * 8)) & 0xFF;
    }

    int src_port=0, dst_port=0;
    // 获取 IP 头部总长度
    unsigned int ip_total_length = ntohs(e->ip_info.tot_len);

    // 提取端口和协议
    if (e->protocol == 6) { // TCP
        src_port = ntohs(e->transport_info.tcp_info.source);
        dst_port = ntohs(e->transport_info.tcp_info.dest);
        BasicPacketInfo pkt(src_ip, dst_ip, src_port, dst_port, e->protocol, e->timestamp_ns / 1000, packet_id_generator); // ns to microsecond
        pkt.setTCPWindow(ntohs(e->transport_info.tcp_info.window));
        pkt.setFlagFIN(e->transport_info.tcp_info.fin);
        pkt.setFlagSYN(e->transport_info.tcp_info.syn);
        pkt.setFlagRST(e->transport_info.tcp_info.rst);
        pkt.setFlagPSH(e->transport_info.tcp_info.psh);
        pkt.setFlagACK(e->transport_info.tcp_info.ack);
        pkt.setFlagURG(e->transport_info.tcp_info.urg);
        pkt.setFlagECE(e->transport_info.tcp_info.ece);
        pkt.setFlagCWR(e->transport_info.tcp_info.cwr);
        unsigned int tcp_header_length = e->transport_info.tcp_info.doff * 4;  // TCP 头部长度
        unsigned int tcp_payload_length = ip_total_length - sizeof(struct iphdr) - tcp_header_length;
        pkt.setPayloadBytes(tcp_payload_length); 
        pkt.setHeaderBytes(tcp_header_length);
        // std::cout<<pkt.fwdFlowId()<<' '<<(pkt.hasFlagFIN()?"fin ":" ")<< (pkt.hasFlagACK()?"ack ":" ")<<std::endl;
        flow_mgr.addPacket(pkt);        
    } else if (e->protocol == 17) { // UDP
        src_port = ntohs(e->transport_info.udp_info.source);
        dst_port = ntohs(e->transport_info.udp_info.dest);
        BasicPacketInfo pkt(src_ip, dst_ip, src_port, dst_port, e->protocol, e->timestamp_ns / 1000000, packet_id_generator);
        unsigned int udp_payload_length = ip_total_length - sizeof(struct iphdr) - sizeof(struct udphdr);
        pkt.setPayloadBytes(udp_payload_length);
        pkt.setHeaderBytes(sizeof(struct udphdr));
        flow_mgr.addPacket(pkt);
    } else {
        // 非 TCP/UDP 协议，暂不处理
        return 0;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    unsigned int ifindex;

    if (argc != 2) {
        printf("Provide interface name\n");
    }

    ifindex = if_nametoindex(argv[1]);
    interface_ip = get_interface_ip(argv[1]);
    printf("Interface %s, index:%d, IP address: %s\n", argv[1], ifindex, inet_ntoa(*(struct in_addr *)&interface_ip));
    
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
    } else  {
        printf("eBPF program attached to traffic control subsystem\n");
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

    printf("Packet Capture Started, Please Ctrl+C to stop\n\n");
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

void handle_sigint(int sig)
{
    printf("Terminating\n");
    exit(0);
}


unsigned int get_interface_ip(char* if_name) {
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd); 
    /* display result */
    return (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr;
}

