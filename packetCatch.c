#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
//https://www.devdungeon.com/content/using-libpcap-c
void print_packet_info(const u_char* packet, struct pcap_pkthdr packet_header) {
    printf("5\n");
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet length: %d\n", packet_header.len);
    // printf("?: %d\n", packet_header.ts);
    // printf("Packet: \n%s\n", packet);
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
}


int main(int argc, char *argv[])
{
    pcap_if_t* devices;
    pcap_t *handle;

    char errMsg[PCAP_ERRBUF_SIZE];
    int result;
    result = pcap_findalldevs(&devices, errMsg); //https://embeddedguruji.blogspot.com/2014/01/pcapfindalldevs-example.html
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