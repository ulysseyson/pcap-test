//pcap-test.h

#include<stdint.h>
#include<stdio.h>
#include<netinet/in.h>
#include<netinet/ether.h>
#include"libnet.h"

void print_mac(libnet_ethernet_hdr*ethernet);
void print_ip(libnet_ipv4_hdr*ipv4);
void print_tcp(libnet_tcp_hdr*tcp);
void print_data(const u_char*packet,int size);
