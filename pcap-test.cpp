
//pcap-test.cpp
#include"pcap-test.h"

void print_mac(libnet_ethernet_hdr*ethernet){
	printf("\nsrc mac : ");
	for(int i=0;i<ETHER_ADDR_LEN;i++){
		printf("%02x",ethernet->ether_shost[i]);
		if(i != ETHER_ADDR_LEN - 1) printf(":");
	}
	printf("\n");
	printf("dst mac :");
	for(int i=0;i<ETHER_ADDR_LEN;i++){
		printf("%02x",ethernet->ether_dhost[i]);
		if(i != ETHER_ADDR_LEN - 1) printf(":");
	}
	printf("\n");
}

void print_ip(libnet_ipv4_hdr*ipv4){
	printf("\nsrc ip : ");
	for(int i=0;i<IP_ADDR_LEN;i++){
		printf("%d",ipv4->ip_src[i]);
		if(i != IP_ADDR_LEN - 1) printf(":");
	}
	printf("\n");
	printf("dst ip : ");
	for(int i=0;i<IP_ADDR_LEN;i++){
		printf("%d",ipv4->ip_dst[i]);
		if(i != IP_ADDR_LEN - 1) printf(":");
	}
	printf("\n");
}

void print_tcp(libnet_tcp_hdr*tcp){
	printf("\nsrc port : %u\n",ntohs(tcp->th_sport));
	printf("dst port : %u\n",ntohs(tcp->th_dport));
}

void print_data(const u_char*packet,int size){
	int offset = sizeof(libnet_ethernet_hdr) + sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr);
	printf("\ndata length : %d", size);
	for(int i=0;i<size;i++){
		if(i >= 10) break;
		printf("%02x", packet[offset + i]);
		printf(" ");
	}
}