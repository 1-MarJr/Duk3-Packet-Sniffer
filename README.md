# Duk3-Packet-Sniffer

This is my first attempt at building a packet sniffer from scratch on C++. 
I taught myself networking basics plus some low-level socket stuff to make this happen. It is nothing fancy yet, but I look towards improving it and adding some filtering, saving to file (maybe), and some other things as I keep using it. 

It is super basic right now - just dumps packet headers into the console. 

# Brief Summary

Duk3 Packet Sniffer is a lightweight, console-based network packet capture tool written in pure C++.
It listens to a network interface, grabs raw packets, and decodes/displays Ethernet, IP, TCP/UDP, and some basic payload info.

Built for learning purposes - not production grade or anything like that.
Tested maily on Linux (Might work on windows as well with some tweaks, but I have not tried that much yet).

# Techs Used

**Language**: C++ (C++11 mainly with some later features here and there)
**Core packet capture**: Raw sockets (using 'AF_PACKET' / 'SOCK_RAW' on Linux)
**Headers and parsing**: Manual bit-level parsing on Ethernet, IPv4, TCP, UDP headers (no external libs for decoding just yet)
**Standard libs**: '<cstring>', '<sys/socket.h>', '<netinet/in.h>', '<arpa/inet.h>', '<net/ethernet.h>', '<unistd.h>', etc.
**Libpcap**: External library used for basic packet headers

# Functionality

Right now it does the following:

Opens a raw socket on the chosen interface
Switches to promiscuous mode if possible
Loops forever capturing packets
For each packet:
Shows Ethernet source/dest MAC + type
If IPv4: source/dest IP, protocol (TCP/UDP/ICMP/etc.)
If TCP/UDP: source/dest ports
Tiny hex dump of the first ~64 bytes of payload
Basic error handling and some colorful console output

# Future Ideas

Protocol dissectors (HTTP, DNS, etc.)
BPF-style filtering (only show port 80 traffic)
Save packets to .pcap file
Stats (packets/sec, top talkers, etc.)

# Why Duk3

just the name of my deceased dog, always wanted to keep his name on my projects as a brand

# License

**MIT license**
Feel free to use, modify, learn from it, whatever suits you. Just keep the copyright notice if you share it.

If you've got any questions, spot bugs, or want to contribute, open an issue on PR
This is pretty much just a learning project, so any feedback is appreciated.
