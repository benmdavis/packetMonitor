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
}

void handle_ipv4_address(char* str, const u_char* addr) {
    sprintf(str, "%d.%d.%d.%d", *addr, *(addr+1), *(addr+2), *(addr+3));
}

void handle_ipv6_address(char* str, const u_char* addr) {
    sprintf(str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", *addr, *(addr+1), *(addr+2), *(addr+3), *(addr+4),*(addr+5),*(addr+6),*(addr+7),*(addr+8),*(addr+9),*(addr+10),*(addr+11),*(addr+12),*(addr+13),*(addr+14),*(addr+15));
}

int handle_ipv4_header(const u_char* ip_header) {
    char srcAddr[15];
    char dstAddr[15];
    u_int8_t ip_vhl = *(ip_header);
    int ip_header_length = (ip_vhl & 0x0f) * 4;
    printf("IP header length (IHL) in bytes: %d bytes\n", ip_header_length);

    int version = ((ip_vhl) & 0xf0) >> 4;
    if (version != 4) {
        printf("Not IPv4. Skipping...\n");
        return -1;
    }
    printf("Version: %d\n", version);
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n");
        return -1;
    }
    const u_char* rawSrc = (ip_header + 12);
    const u_char* rawDst = (ip_header + 16);
    handle_ipv4_address(srcAddr, rawSrc);
    handle_ipv4_address(dstAddr, rawDst);
    printf("Source: %s\n", srcAddr);
    printf("Destination: %s\n", dstAddr);
    return ip_header_length;
}

int handle_ipv6_header(const u_char* ip_header) {
    char srcAddr[128];
    char dstAddr[128];
    int ip_header_length = 40; //length is hardcoded in RFC 2460
    printf("IP header length (IHL) in bytes: %d bytes\n", ip_header_length);

    u_int8_t ip_vhl = *(ip_header);
    
    int version = ((ip_vhl) & 0xf0) >> 4;
    if (version != 6) {
        printf("Not IPv6. Skipping...\n");
        return -1;
    }
    printf("Version: %d\n", version);
    u_char nextHeaderType = *(ip_header + 6);
    if(nextHeaderType != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n");
        return -1;
    }
    const u_char* rawSrc = (ip_header + 8);
    const u_char* rawDst = (ip_header + 24);
    handle_ipv6_address(srcAddr, rawSrc);
    handle_ipv6_address(dstAddr, rawDst);
    printf("Source: %s\n", srcAddr);
    printf("Destination: %s\n", dstAddr);
    return ip_header_length;
}

void handle_ip4_packet(const struct pcap_pkthdr *header, const u_char *packet){
    const u_char *ip_header;
    const u_char *tcp_header;
    const char *payload;

    int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;
    ip_header = packet + ethernet_header_length;
    ip_header_length = handle_ipv4_header(ip_header);
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
    return;
}

void handle_arp_packet(const struct pcap_pkthdr *header, const u_char *packet){
    char srcAddr[15];
    char dstAddr[15];
    printf("ARP Packet:\n");
    struct arphdr *arpheader = (struct arphdr*)packet + 14;
    int hln = arpheader->ar_hln;
    int pln = arpheader->ar_pln;
    int arpLength = sizeof(arpheader) + 2*hln + 2*pln;
    printf("ARP Packet length: %d bytes", arpLength);
    const u_char* rawSrc =  (((const u_char *)((arpheader)+1))+  hln);
    const u_char* rawDst =  (((const u_char *)((arpheader)+1))+2*hln+pln);
    handle_ipv4_address(srcAddr, rawSrc);
    handle_ipv4_address(dstAddr, rawDst);
    printf("Source: %s\n", srcAddr);
    printf("Destination: %s\n", dstAddr);

}

void handle_ip6_packet(const struct pcap_pkthdr *header, const u_char *packet){
    const u_char *ip_header;
    const u_char *tcp_header;
    const char *payload;

    int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    ip_header = packet + ethernet_header_length;
    ip_header_length = handle_ipv6_header(ip_header);

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
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    print_packet_info(packet, *header);
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    u_int16_t packetType = ntohs(eth_header->ether_type);
    if(packetType == ETHERTYPE_IP) handle_ip4_packet(header, packet);
    else if(packetType == ETHERTYPE_ARP) handle_arp_packet(header, packet);
    else if(packetType == ETHERTYPE_IPV6) handle_ip6_packet(header, packet);
    else {
            printf("If you're seeing this, unhandled packet type reached: %x\n", packetType);
    }
    printf("###END PACKET INFO###\n\n");
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
    pcap_close(handle);
	return(0);
}