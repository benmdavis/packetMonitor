# packetMonitor
(WIP) Packet sniffer for local network.
Goal: A local network packet sniffer built in C using the libpcap library that outputs data in an (TBD) format that is then displayed using (TBD) framework via Python.
Current state: Packet's are detected and basic information is displayed. 
Next steps: Display and parse the packet payload.

Resources Used:
Guide to libpcap: https://www.devdungeon.com/content/using-libpcap-c
Usage of pcap_find_all_devs: https://embeddedguruji.blogspot.com/2014/01/pcapfindalldevs-example.html

Build Instructions:
- gcc packetCatch.c -lpcap -o packetCatch

Run Instructions:
- Must run as sudo to allow monitoring on network device.
- sudo ./packetCatch