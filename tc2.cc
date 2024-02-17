#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include "tc2.h"
#include "uthash.h"
#include <sys/time.h>
#include <sys/ioctl.h>
#include "tc2.skel.h"
#include <pthread.h>
#include <unistd.h>
#include <algorithm>

#include <unordered_map>
#include <unordered_set>
#include <iostream>

__u32 interface_ip;

typedef struct {
    __u32 ip;
    __u16 port;
} sock_addr;

typedef struct {
    sock_addr addr1;
    sock_addr addr2;
} conn_key;

typedef struct {
    unsigned long long int fwd_bytes;
    unsigned long long int bwd_bytes;
}conn_info;

unsigned int get_interface_ip(char* if_name);

// ip1:port1 -> ip2:port2 = ip2:port2 -> ip1:port1

// 哈希函数的自定义实现
struct connection_key_hash {
    std::size_t operator()(const conn_key& key) const {
        return std::hash<unsigned int>()(key.addr1.ip) ^
               std::hash<unsigned int>()(key.addr2.ip) ^
               std::hash<unsigned short>()(key.addr1.port) ^
               std::hash<unsigned short>()(key.addr2.port);
    }
};

// 相等比较函数的自定义实现
struct connection_key_equal {
    bool operator()(const conn_key& lhs, const conn_key& rhs) const {
        return lhs.addr1.ip==rhs.addr1.ip &&
               lhs.addr1.port==rhs.addr1.port &&
               lhs.addr2.ip==rhs.addr2.ip &&
               lhs.addr2.port==rhs.addr2.port;
    }
};

std::unordered_map<conn_key, conn_info, connection_key_hash, connection_key_equal> conn_map;
std::unordered_map<conn_key, int, connection_key_hash, connection_key_equal> conn_fin_map;
std::unordered_map<conn_key, int, connection_key_hash, connection_key_equal> conn_syn_map;
std::unordered_set<conn_key, connection_key_hash, connection_key_equal> conn_key_to_remove_set; // remove on every 1 second
pthread_mutex_t conn_map_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t conn_key_to_remove_set_mutex = PTHREAD_MUTEX_INITIALIZER;


#define FORWARD 0 
#define BACKWARD 1


void delete_conn(const conn_key& key) {
    pthread_mutex_lock(&conn_map_mutex);
    conn_map.erase(key);
    pthread_mutex_unlock(&conn_map_mutex);
}

void handle_sigint(int sig)
{
    printf("Terminating\n");
    exit(0);
}

// 添加或更新连接信息
void add_or_update_connection(const conn_key& key, int bytes, int direction) {

    // 获取互斥锁
    pthread_mutex_lock(&conn_map_mutex);
    // 根据数据包的流向更新流量信息
    if (direction == FORWARD) {
        conn_map[key].fwd_bytes += bytes;
    } else if (direction == BACKWARD) {
        conn_map[key].bwd_bytes += bytes;
    }
    // 释放互斥锁
    pthread_mutex_unlock(&conn_map_mutex);
}


conn_key make_key(sock_addr addr1, sock_addr addr2){
    if((addr1.ip!=interface_ip)||(addr1.ip==addr2.ip&&addr1.port>addr2.port)) std::swap(addr1,addr2);
    return {addr1,addr2};
}

// fix it: not establish的时候，流量没有统计
int handle_event(void *ctx, void *data, size_t len)
{
    struct event *e = (struct event *)data;

    auto key=make_key({e->ip_info.saddr,ntohs(e->tcp_info.source)},{e->ip_info.daddr,ntohs(e->tcp_info.dest)});
    // ingress->forward, 即dst=interface时是
    int direction = e->ip_info.daddr == interface_ip? FORWARD : BACKWARD;

    // 添加或更新连接信息
    if(e->tcp_info.syn&&e->tcp_info.ack) conn_syn_map[key]=1; // 确认连接后，才进行统计 但是这样没法搞ddos，再考虑考虑
    if(conn_syn_map.find(key)!=conn_syn_map.end()&&!e->tcp_info.syn&&e->tcp_info.ack) add_or_update_connection(key, ntohs(e->ip_info.tot_len), direction);    


    // 为什么conn_count在不断增多，和系统中的tcp连接数不匹配？因为累积了NOT_ESTABLISH的，当然FIN也就无从谈起，不会执行delete_conn
    // 四次挥手 倒数第二次
    if (e->tcp_info.fin&&e->tcp_info.ack) conn_fin_map[key]=1;

    if(conn_fin_map.find(key)!=conn_fin_map.end()&&!e->tcp_info.fin&&e->tcp_info.ack){// 四次挥手最后一次  
        conn_fin_map.erase(key);
        pthread_mutex_lock(&conn_key_to_remove_set_mutex);
        conn_key_to_remove_set.insert(key);
        pthread_mutex_unlock(&conn_key_to_remove_set_mutex);
    }
    
    return 0;
}



void *timer_handler1(void *arg) {
    static int time_count=0;
    while (1) {
        sleep(1);
        //在这里执行您的任务
        printf("------------------------------------------------------------------------------------------\n");
        int conn_count=0;
        pthread_mutex_lock(&conn_map_mutex);
        for (auto it = conn_map.begin(); it != conn_map.end(); ++it) {
            conn_count++;
            auto key=it->first;
            auto& info=it->second; //引用
            char ip1_str[INET_ADDRSTRLEN];
            char ip2_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(key.addr1.ip), ip1_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(key.addr2.ip), ip2_str, INET_ADDRSTRLEN);
            printf("At %d sec, %s:%u - %s:%u, Forward Bytes(接收字节速度): %llu KB/s, Backward Bytes(发送字节速度): %llu KB/s\n",
                    ++time_count, ip1_str, key.addr1.port, ip2_str, key.addr2.port,
                    info.fwd_bytes, info.bwd_bytes);
            info.fwd_bytes = 0; // 清空累积的正向字节数
            info.bwd_bytes = 0; // 清空累积的反向字节数
        }
        pthread_mutex_unlock(&conn_map_mutex);

        pthread_mutex_lock(&conn_key_to_remove_set_mutex);
        for(auto key:conn_key_to_remove_set){
            delete_conn(key);
        }
        conn_key_to_remove_set.clear();
        pthread_mutex_unlock(&conn_key_to_remove_set_mutex);
        // delete_conn(key);
        printf("connections count:%d\n",conn_count);
    }
    return NULL;
}


int main(int argc, char *argv[])
{
    pthread_t tid;
    std::cout<<"hello!"<<std::endl;
    // return 0;
    pthread_create(&tid, NULL, timer_handler1, NULL);
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



void print_iphdr(struct iphdr* ip_info){
    printf("IP Header:\n");
    printf("  Version: %u\n", ip_info->version);
    printf("  Header Length: %u bytes\n", ip_info->ihl * 4);
    printf("  Total Length: %u bytes\n", ntohs(ip_info->tot_len));
    printf("  Protocol: %u\n", ip_info->protocol);
    printf("  Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_info->saddr));
    printf("  Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_info->daddr));
}

void print_tcphdr(struct tcphdr* tcp_info){
    // Print TCP header
    printf("TCP Header:\n");
    printf("  Source Port: %u\n", ntohs(tcp_info->source));
    printf("  Destination Port: %u\n", ntohs(tcp_info->dest));
    printf("  TCP Flags: ");
    if (tcp_info->ack) printf("ACK \n");
    if (tcp_info->syn) printf("SYN ");
    if (tcp_info->fin) printf("FIN x->");
    if (tcp_info->rst) printf("RST ");
    if (tcp_info->psh) printf("PSH ");
    if (tcp_info->urg) printf("URG ");
    printf("\n");
    printf("  Sequence Number: %u\n", ntohl(tcp_info->seq));
    printf("  Acknowledgment Number: %u\n", ntohl(tcp_info->ack_seq));
    printf("  Data Offset: %u bytes\n", tcp_info->doff * 4);
    printf("  Window Size: %u\n", ntohs(tcp_info->window));
    printf("  Checksum: 0x%x\n", ntohs(tcp_info->check));
    printf("  Urgent Pointer: %u\n", ntohs(tcp_info->urg_ptr));
}

unsigned int get_interface_ip(char* if_name) {
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET; 
    /* I want IP address attached to "eth0" */
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd); 
    /* display result */
    return (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr;
}
