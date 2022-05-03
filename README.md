# packetMonitor
(WIP) Packet sniffer for local network.
Goal: A local network packet sniffer built in C using the libpcap library that outputs data in an (TBD) format that is then displayed using (TBD) framework via Python.
Current state: IP data handled, packet is printing hex data now. 
Next steps: Finish ipv6 address handling function. Handle other packet types (ARP, etc).

Resources Used:
Guide to libpcap: https://www.devdungeon.com/content/using-libpcap-c
Usage of pcap_find_all_devs: https://embeddedguruji.blogspot.com/2014/01/pcapfindalldevs-example.html
RFC 791: https://datatracker.ietf.org/doc/html/rfc791
RFC 793: https://datatracker.ietf.org/doc/html/rfc793

Build Instructions:
- gcc packetCatch.c -lpcap -o packetCatch

Run Instructions:
- Must run as sudo to allow monitoring on network device.
- sudo ./packetCatch