#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "net.h"
#define data 16

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {

     if (argc != 2) {
        usage();
        return -1;
     }

    struct libnet_ethernet_hdr* eth;
    struct libnet_ipv4_hdr* ip;
    struct libnet_tcp_hdr* tcp;

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
          fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
           return -1;
    }

    while(true) {
       struct pcap_pkthdr* header;
       const u_char* packet; //packet start point
       eth = (struct libnet_ethernet_hdr* )packet;
       ip = (struct libnet_ipv4_hdr* )packet;
       tcp = (struct libnet_tcp_hdr* )packet;
       int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
                if (res == -1 || res == -2) {
                    printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                    break;
                }
                printf("       Ethernet Header\n");
                printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
                    eth->ether_shost[0],eth->ether_shost[1],
                    eth->ether_shost[2],eth->ether_shost[3],
                    eth->ether_shost[4],eth->ether_shost[5]);
                printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
                    eth->ether_dhost[0],eth->ether_dhost[1],
                    eth->ether_dhost[2],eth->ether_dhost[3],
                    eth->ether_dhost[4],eth->ether_dhost[5]);
                printf("---------------------------");
                printf("\n\n");
                /////////////////////////////////////////////////////
                printf("       IP Header\n");
                printf("src IP : %s\n", ip ->ip_src);
                printf("dst IP : %s\n", ip ->ip_dst);
                printf("---------------------------");
                printf("\n\n");
                ///////////////////////////////////////////////////////
                printf("       TCP Header\n");
                printf("src port : %d\n", tcp->th_sport);
                printf("dst port : %d\n", tcp->th_dport);
                printf("---------------------------");
                printf("\n\n");
                //////////////////////////////////////////////////////
                printf("       Data\n");
                for(int i=0; i<data; i++){
                    printf("%p", packet);
                }
                printf("---------------------------");
                printf("\n\n");


            }
    pcap_close(handle);
}

