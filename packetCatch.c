#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void print_packet_info(const u_char* packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet length: %d\n", packet_header.len);
    // printf("?: %d\n", packet_header.ts);

}
void handle_address(char* str, const u_char* addr) {
    sprintf(str, "%d.%d.%d.%d", *addr, *(addr+1), *(addr+2), *(addr+3));
}
void handle_port(char * str, const u_char* port) {
    printf("port: %d\n", *port);
}
int handle_ip_header(const u_char* ip_header) {
    char srcAddr[15];
    char dstAddr[15];
    u_int8_t ip_vhl = *(ip_header);
    int ip_header_length = (ip_vhl & 0x0f) * 4;
    printf("IP header length (IHL) in bytes: %d bytes\n", ip_header_length);

    int version = ((ip_vhl) & 0xf0) >> 4;
    if (version != 4) {
        printf("Not IPv4. Skipping...\n\n");
        return -1;
    }
    printf("Version: %d\n", version);
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return -1;
    }
    const u_char* rawSrc = (ip_header + 12);
    const u_char* rawDst = (ip_header + 16);
    handle_address(srcAddr, rawSrc);
    handle_address(dstAddr, rawDst);
    printf("Source: %s\n", srcAddr);
    printf("Destination: %s\n", dstAddr);
    return ip_header_length;
}


void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    print_packet_info(packet, *header);
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) 
    {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }
    const u_char *ip_header;
    const u_char *tcp_header;
    const char *payload;

    int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;
    ip_header = packet + ethernet_header_length;
    ip_header_length = handle_ip_header(ip_header);
    if(ip_header_length == -1) {
        return;
    }
    tcp_header = packet + ethernet_header_length + ip_header_length;
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    int total_header_length = ethernet_header_length + ip_header_length + tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_header_length);

    payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_header_length; 
    printf("Payload:\n", payload);
    if (payload_length > 0) { 
        const u_char *temp_pointer = payload; 
        int byte_count = 0; 
        while (byte_count++ < payload_length) {
            printf("%.2x", *temp_pointer); 
            temp_pointer++; 
        }
        printf("\n"); 
    } 
    return;
}


int main(int argc, char *argv[])
{
    pcap_if_t* devices;
    pcap_t *handle;

    char errMsg[PCAP_ERRBUF_SIZE];
    int result;
    result = pcap_findalldevs(&devices, errMsg); 
	if (result == -1) {
		fprintf(stderr, "Couldn't find default device: %s\n", errMsg);
		return(2);
	}


    const u_char* packet;
    struct pcap_pkthdr packet_header;
    printf("Attempting to open monitoring on %s\n", devices->name);
    int snapshot = 1000;
    int promiscous = 0;
    int timeout = 10000;
    handle = pcap_open_live(devices->name, snapshot, promiscous, timeout, errMsg);

    if(handle == NULL) {
        printf("%s\n", errMsg);
        return(2);
    }
    printf("Device opened!\n");
    pcap_loop(handle, 0, packet_handler, NULL);

	return(0);
}