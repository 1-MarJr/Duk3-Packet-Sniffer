#include <pcap.h> /*Main libpcap header for packet capture*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> /*Network address conversion functions (inet_ntoa, etc.)*/
#include <net/ethernet.h> /*Ethernet frame structure definitions*/
#include <netinet/ip.h> /*IP header structure definitions*/
#include <netinet/tcp.h> /*TCP header structure definitions*/
#include <netinet/udp.h> /*UDP header structure definitions*/

// Callback function - gets called for each captured packet
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  printf("\n=== Packet Captured ===\n");
  printf("Packet length: %d bytes\n", header->len);

  struct  ether_header *eth=(struct ether_header *) packet;

  u_short ether_type=ntohs(eth->ether_type);
  printf("Ethernet Type: 0x%04x ", ether_type);

  if(ether_type==ETHERTYPE_IP)
  {
    printf("(IPv4)\n");
  } else if(ether_type==ETHERTYPE_IPV6)
  {
    printf("(IPv6)\n");
  } else if(ether_type==ETHERTYPE_ARP)
  {
    printf("(ARP)\n");
  }
  
  // Only process IPv4 packets
  if(ether_type==ETHERTYPE_IP)
  {
    // IP header starts right after Ethernet header (14 bytes in)
    struct iphdr *ip=(struct iphdr *)(packet+sizeof(struct ether_header));

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);

    printf("Source IP: %s\n", src_ip);
    printf("Dest IP: %s\n", dst_ip);

    // Get the protocol (TCP, UDP, ICMP, etc...)
    u_char protocol=ip->protocol;
    printf("Protocol: ");

    if(protocol==IPPROTO_TCP)
    {
      printf("TCP\n");

      // TCP header starts after IP header
      // IP header length is variable: (ip->ihl*4) bytes
      struct tcphdr *tcp=(struct tcphdr *)(packet+sizeof(struct ether_header)+(ip->ihl*4));

      // Extract TCP ports
      u_short src_port=ntohs(tcp->th_sport);
      u_short dst_port=ntohs(tcp->th_dport);

      printf("Source Port: %d\n", src_port);
      printf("Dest Port: %d\n", dst_port);

      // Check TCP flags
      u_char flags=tcp->th_flags;
      printf("Flags: ");

      if(flags&TH_SYN) printf("SYN ");
      if(flags&TH_ACK) printf("ACK ");
      if(flags&TH_FIN) printf("FIN ");
      if(flags&TH_RST) printf("RST ");
      printf("\n");
    } else if(protocol==IPPROTO_UDP)
    {
      printf("UDP\n");
      struct udphdr *udp=(struct udphdr *)(packet+sizeof(struct ether_header)+(ip->ihl*4));

      u_short src_port=ntohs(udp->uh_sport);
      u_short dst_port=ntohs(udp->uh_dport);

      printf("Source Port: %d\n", src_port);
      printf("Dest Port: %d\n", dst_port);
    } else if(protocol==IPPROTO_ICMP)
    {
      printf("ICMP");
    }
  }
}

int main()
{
  char errbuf[PCAP_ERRBUF_SIZE]; // error buffer for pcap functions
  pcap_t *handle; // Handle to the pcap session
  char filter_exp[]=""; // Empty filter=capture all 
  struct bpf_program fp; // Compiled filter 

  // Get list of available network devices
  pcap_if_t *alldevs, *d;
  if(pcap_findalldevs(&alldevs, errbuf)==-1)
  {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    return 1;
  }

  if(alldevs==NULL)
  {
    fprintf(stderr, "No interfaces found\n");
    return 1;
  }

  printf("Available network interfaces:\n");
  for(d=alldevs; d!=NULL; d=d->next)
  {
    printf("  - %s\n", d->name);
  }

  // Open the first available network interface
  const char *device=alldevs->name;
  printf("\nCapturing on device: %s\n", device);

  // Open in live mode with default parameters
  handle=pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);

  if(handle==NULL)
  {
    fprintf(stderr, "Couldn't open device: %s\n", errbuf);
    return 1;
  }

  // Compile the filter (empty=no filter)
  if(pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN)==-1)
  {
    fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
    return 1;
  }

  // Apply the filter to the session
  if(pcap_setfilter(handle, &fp)==-1)
  {
    fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
    return 1;
  }

  // Start packet capture loop
  printf("Starting packet capture. Press Ctrl+C to stop.\n\n");

  pcap_loop(handle, -1, packet_handler, NULL);

  // Cleanup
  pcap_freecode(&fp); // Free compiled filter 
  pcap_close(handle); // Close capture session 
  pcap_freealldevs(alldevs); // Free device list 
  
  return 0;
}
