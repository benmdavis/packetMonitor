#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void print_packet_info(const u_char* packet, struct pcap_pkthdr packet_header) {
    printf("5\n");
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet length: %d\n", packet_header.len);
    // printf("?: %d\n", packet_header.ts);

}
void handle_address(char* str, u_char* srcAddr) {
    int i = 0;
    char* a = itoa(srcAddr);
    printf("%d\n",a);
    srcAddr = srcAddr + 1;
    char* b = itoa(srcAddr);
    printf("%d\n",b);

    // int c
    // int d
    // while (i<15){
    //     str[i] = srcAddr
    // }
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
    char* srcAddr[15];
    u_char *payload;

    int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;
    int version;
    ip_header = packet + ethernet_header_length;

    u_int8_t ip_vhl = *(ip_header);
    ip_header_length = (ip_vhl & 0x0f) * 4;
    printf("IP header length (IHL) in bytes: %d bytes\n", ip_header_length);

    version = ((ip_vhl) & 0xf0) >> 4;
    printf("Version: %d\n", version);
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }
    const u_char* rawSrc = (ip_header + 12);
    handle_address(srcAddr, rawSrc);
    printf("Source: %d\n", srcAddr);
    tcp_header = packet + ethernet_header_length + ip_header_length;
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    int total_header_length = ethernet_header_length + ip_header_length + tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_header_length);

    payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);

    payload = packet + total_header_length;

    // u_char *temp = payload;
    // int count = 0;
    // payload[payload_length] = '\0';
    // while(count < payload_length) {
    //     if(isprint(*temp)) {
    //         printf("%c", *temp);
    //     }
    //     else {
    //         printf(".");
    //     }
    //     temp++;
    //     count++;
    // }
    // printf("\n");

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